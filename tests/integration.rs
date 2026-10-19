#[test]
fn subprocess_protocol_tests() {
    let status = std::process::Command::new("python3")
        .arg("tests/integration.py")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("PINENTRY_OP_TEST_BINARY", env!("CARGO_BIN_EXE_pinentry-op"))
        .status()
        .expect("Python 3 is required for subprocess integration tests");
    assert!(status.success(), "subprocess integration tests failed");
}
