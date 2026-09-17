use assert_cmd::Command;
#[test]
fn init_creates_only_config_and_does_not_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("quantum-ipsec")
        .unwrap()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .success();
    assert!(dir.path().join("quantum-ipsec.toml").exists());
    assert!(!dir.path().join("quantum-ipsec.keypair").exists());
    Command::cargo_bin("quantum-ipsec")
        .unwrap()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .failure();
}
#[test]
fn unavailable_operations_fail_closed() {
    for args in [
        vec!["connect", "--peer", "127.0.0.1"],
        vec![
            "encrypt", "--sa", "dummy", "--input", "dummy", "--output", "dummy",
        ],
        vec!["decrypt", "--sa", "dummy", "--input", "dummy"],
        vec!["monitor"],
    ] {
        Command::cargo_bin("quantum-ipsec")
            .unwrap()
            .args(args)
            .assert()
            .failure();
    }
}
#[test]
fn status_reports_disconnected() {
    let output = Command::cargo_bin("quantum-ipsec")
        .unwrap()
        .args(["status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["runtime"], "not-connected");
    assert!(v["active_sas"].is_null());
}
#[test]
fn invalid_config_does_not_silently_fallback() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("quantum-ipsec")
        .unwrap()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .success();
    for (key, value) in [
        ("max_sas", "no"),
        ("debug", "yes"),
        ("sa_lifetime", "0"),
        ("unknown", "1"),
    ] {
        Command::cargo_bin("quantum-ipsec")
            .unwrap()
            .current_dir(dir.path())
            .args(["config", "set", key, value])
            .assert()
            .failure();
    }
}
#[test]
fn benchmark_rejects_unbounded_input() {
    Command::cargo_bin("quantum-ipsec")
        .unwrap()
        .args(["benchmark", "--payload-size", "99999999"])
        .assert()
        .failure();
}
