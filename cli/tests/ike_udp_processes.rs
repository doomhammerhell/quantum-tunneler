use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, UdpSocket},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn(
    role: &str,
    local: &str,
    peer_id: &str,
    peer: SocketAddr,
    child_sa: bool,
) -> (Process, SocketAddr) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_quantum-ipsec"));
    command.arg("ike-handshake");
    if child_sa {
        let (local, peer) = if role == "initiator" {
            ("10.0.0.1", "10.0.0.2")
        } else {
            ("10.0.0.2", "10.0.0.1")
        };
        command.args(["--local-inner-ip", local, "--peer-inner-ip", peer]);
    }
    let child = command
        .args([
            "--role",
            role,
            "--bind",
            "127.0.0.1:0",
            "--peer",
            &peer.to_string(),
            "--local-id",
            local,
            "--peer-id",
            peer_id,
            "--psk-stdin",
            "--timeout-secs",
            "2",
            "--output-format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut process = Process(child);
    process
        .0
        .stdin
        .take()
        .unwrap()
        .write_all("07".repeat(32).as_bytes())
        .unwrap();
    let stderr = process.0.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stderr).read_line(&mut line).unwrap();
        let _ = tx.send(line);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("CLI did not bind");
    let addr = line
        .trim()
        .strip_prefix("IKE UDP bound: ")
        .expect("unexpected startup output")
        .parse()
        .unwrap();
    (process, addr)
}
fn finish(mut process: Process) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            break;
        }
        assert!(Instant::now() < deadline, "CLI exceeded its deadline");
        thread::sleep(Duration::from_millis(10));
    }
    let mut output = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(!output.contains(&"07".repeat(32)), "PSK leaked to output");
    serde_json::from_str(&output).unwrap()
}
#[test]
fn two_cli_processes_authenticate_despite_udp_loss() {
    exchange(false);
}
#[test]
fn two_cli_processes_negotiate_child_despite_final_response_loss() {
    exchange(true);
}
fn exchange(child_sa: bool) {
    let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
    relay
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let peer = relay.local_addr().unwrap();
    let (responder, ra) = spawn("responder", "server", "client", peer, child_sa);
    let (initiator, ia) = spawn("initiator", "client", "server", peer, child_sa);
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let proxy = thread::spawn(move || {
        let mut buffer = [0; 4096];
        let mut dropped_init = false;
        let mut dropped_auth = false;
        let deadline = Instant::now() + Duration::from_secs(6);
        while !done.load(Ordering::Relaxed) && Instant::now() < deadline {
            let Ok((len, source)) = relay.recv_from(&mut buffer) else {
                continue;
            };
            if source == ia && !dropped_init {
                dropped_init = true;
                continue;
            }
            if source == ra && buffer[18] == if child_sa { 36 } else { 35 } && !dropped_auth {
                dropped_auth = true;
                continue;
            }
            relay
                .send_to(&buffer[..len], if source == ia { ra } else { ia })
                .unwrap();
        }
        assert!(dropped_init && dropped_auth);
    });
    let i = finish(initiator);
    let r = finish(responder);
    stop.store(true, Ordering::Relaxed);
    proxy.join().unwrap();
    for report in [&i, &r] {
        assert_eq!(
            report["result"],
            if child_sa {
                "authenticated-child-sa"
            } else {
                "authenticated-childless-handshake"
            }
        );
        assert_eq!(report["child_sa_established"], child_sa);
        assert_eq!(report["tunnel_established"], false);
        assert_eq!(report["session_retained"], false);
    }
    if child_sa {
        assert_eq!(i["child_inbound_spi"], r["child_outbound_spi"]);
        assert_eq!(i["child_outbound_spi"], r["child_inbound_spi"]);
    }
    assert_eq!(i["initiator_spi"], r["initiator_spi"]);
    assert_eq!(i["responder_spi"], r["responder_spi"]);
    assert!(i["timed_retries"].as_u64().unwrap() >= 2);
}
#[test]
fn malformed_psk_fails_without_binding_or_echoing_input() {
    let mut command = assert_cmd::Command::cargo_bin("quantum-ipsec").unwrap();
    let output = command
        .args([
            "ike-handshake",
            "--role",
            "initiator",
            "--bind",
            "127.0.0.1:0",
            "--peer",
            "127.0.0.1:12345",
            "--local-id",
            "client",
            "--peer-id",
            "server",
            "--psk-stdin",
        ])
        .write_stdin("not-a-valid-secret")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("not-a-valid-secret"));
    assert!(!stderr.contains("IKE UDP bound:"));
}
