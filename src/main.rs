extern crate base64;

mod lib;

use self::base64::encode;

fn main() {
    let security_token = lib::node_sspi::acquire_credentials_handle("Negotiate".to_string(), "HTTP/win-5knflpj2ucf.a.cell".to_string());
    println!("HandlePtr: {}", encode(&security_token));
}