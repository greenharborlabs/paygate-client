use std::process::ExitCode;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("paygate platform-smoke 0.0.0");
            ExitCode::SUCCESS
        }
        Some("--help") => {
            println!("Usage: paygate [--version|--help]");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("platform smoke stub accepts only --version or --help");
            ExitCode::from(2)
        }
    }
}
