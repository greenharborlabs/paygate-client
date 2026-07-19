use std::process::Command;

fn paygate(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_paygate"))
        .args(args)
        .output()
        .expect("platform stub must execute")
}

#[test]
fn version_succeeds_with_stable_output() {
    let output = paygate(&["--version"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"paygate platform-smoke 0.0.0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn help_succeeds_with_stable_output() {
    let output = paygate(&["--help"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"Usage: paygate [--version|--help]\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn missing_argument_fails_closed() {
    let output = paygate(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"platform smoke stub accepts only --version or --help\n"
    );
}

#[test]
fn unknown_argument_fails_closed() {
    let output = paygate(&["--unknown"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"platform smoke stub accepts only --version or --help\n"
    );
}
