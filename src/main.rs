use clap::Parser;

#[tokio::main]
async fn main() {
    let _runtime_lock = match paygate::runtime_lock::acquire_packaged_runtime_lock() {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("paygate maintenance mode: {error}");
            std::process::exit(75);
        }
    };
    let cli = paygate::cli::Cli::parse();
    if cli.version {
        println!("{}", paygate::VERSION);
        return;
    }
    std::process::exit(paygate::cli::run_cli(cli).await);
}
