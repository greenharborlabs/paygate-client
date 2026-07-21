//! Credential-free qualification probe.  Payment authority stays in the
//! installed protected runner; this binary only emits a bounded request.
use std::io::{self, Read};

fn main() {
    let mut request = String::new();
    if io::stdin().read_to_string(&mut request).is_err() || request.len() > 4096 {
        std::process::exit(2);
    }
    // The runner deliberately does not accept backend, invoice, credential, or cap
    // selection from this probe.  Keep the output a fixed, non-sensitive intent.
    if request.contains("invoice") || request.contains("preimage") || request.contains("credential")
        || request.contains("backend") || request.contains("cap") {
        std::process::exit(2);
    }
    println!("{{\"qualification_request\":\"candidate-probe-v1\"}}");
}
