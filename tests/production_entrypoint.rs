#[test]
fn production_entrypoint_acquires_packaged_lock_before_parsing_or_running_cli() {
    let source = include_str!("../src/main.rs");
    let acquire = source
        .find("paygate::runtime_lock::acquire_packaged_runtime_lock()")
        .expect("production main must acquire the packaged runtime lock");
    let maintenance_exit = source
        .find("std::process::exit(75)")
        .expect("runtime-lock failure must retain the maintenance exit code");
    let parse = source
        .find("paygate::cli::Cli::parse()")
        .expect("production main must parse the CLI");
    let run = source
        .find("paygate::cli::run_cli(cli).await")
        .expect("production main must dispatch the CLI");

    assert!(acquire < maintenance_exit);
    assert!(maintenance_exit < parse);
    assert!(parse < run);
}
