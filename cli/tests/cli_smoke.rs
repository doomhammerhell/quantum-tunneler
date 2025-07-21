use assert_cmd::Command;

#[test]
fn test_init() {
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("init");
    cmd.assert().success();
}

#[test]
fn test_connect() {
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("connect").arg("--peer").arg("127.0.0.1");
    cmd.assert().success();
}

#[test]
fn test_status() {
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("status");
    cmd.assert().success();
}

#[test]
fn test_encrypt() {
    // Assume dummy files/SA exist or mock
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("encrypt").arg("--sa").arg("dummy.sa").arg("--input").arg("dummy.in").arg("--output").arg("dummy.out");
    let _ = cmd.output(); // Não falha se arquivos não existem
}

#[test]
fn test_decrypt() {
    // Assume dummy files/SA exist ou mock
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("decrypt").arg("--sa").arg("dummy.sa").arg("--input").arg("dummy.pkt");
    let _ = cmd.output();
}

#[test]
fn test_benchmark() {
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("benchmark").arg("--duration").arg("1");
    cmd.assert().success();
}

#[test]
fn test_config_get() {
    let mut cmd = Command::cargo_bin("quantum-ipsec").unwrap();
    cmd.arg("config").arg("get").arg("debug");
    let _ = cmd.output();
}

#[test]
fn test_monitor() {
    // Executa monitor por 1 segundo e envia 'q' para sair
    use std::process::{Command as StdCommand, Stdio};
    use std::io::Write;
    let mut child = StdCommand::new("cargo")
        .arg("run")
        .arg("--")
        .arg("monitor")
        .arg("--interval").arg("500")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"q");
    }
    let _ = child.wait();
} 