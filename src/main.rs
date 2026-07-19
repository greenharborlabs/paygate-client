fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    match args.next().as_deref() {
        Some("--version" | "-V") => println!("paygate {}", paygate::VERSION),
        Some("--help" | "-h") | None => {
            println!("Paygate command-line client\n\nUsage: paygate [OPTIONS]");
        }
        Some(_) => {
            eprintln!("command implementation is not available in the qualification skeleton");
            std::process::exit(2);
        }
    }
}
