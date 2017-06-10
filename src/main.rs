extern crate base64;

mod lib;

use self::base64::{decode, encode};

fn main() {
    let security_token = lib::node_sspi::initialize_security_context("Negotiate".to_string(), "HTTP/win-5knflpj2ucf.a.cell".to_string());
    println!("First token: {}", encode(&security_token.token));
    let mut input = String::new();
    ::std::io::stdin().read_line(&mut input);
    input = input.trim().to_string();
    println!("Input {}", input);
    let decoded = decode(&input);
    match decoded {
        Ok(unwrapped) => {
            let buffer = unwrapped;
            let input_token = lib::node_sspi::SecurityContext {
                credentials_handle: security_token.credentials_handle,
                context_handle: security_token.context_handle,
                token: buffer
            };
            let second_token = lib::node_sspi::initialize_security_context_with_input("win-5knflpj2ucf.a.cell".to_string(), input_token);
            println!("Second token: {}", encode(&second_token.token));
        },
        Err(err) => {
            println!("Error: {:?}", err);
        }
    }
}