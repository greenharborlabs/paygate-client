use clap::Parser;

fn main() {
    let cli = paygate::cli::Cli::parse();
    if cli.version {
        println!("{}", paygate::VERSION);
        return;
    }
    std::process::exit(paygate::cli::run_cli(cli));
}
