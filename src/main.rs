mod lib;

fn main() {
    let ptr = lib::node_sspi::acquire_credentials_handle("Negotiate".to_string(), "HTTP/win-5knflpj2ucf.a.cell".to_string());
    println!("HandlePtr: {:p}", ptr);
}