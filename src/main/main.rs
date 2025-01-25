use std::{env, process};
extern crate aes256ctrbench;
extern crate rand;
extern crate rustc_serialize;

fn main() {
    if std::env::args().len() != 2 {
        println!("Usage: ./aes256ctrbench <plaintext>");
        process::exit(1);
    }

    let args: Vec<String> = env::args().collect();

    //let plaintext = &args[1];
    let plaintext = args[1].clone();

    // Creates u8 bytes arr
    let plaintext_bytes = plaintext.as_bytes();

    // Generates a 16 byte nonce
    let nonce = aes256ctrbench::generate_nonce();

    //let key = aes256ctrbench::generate_key();
    // Key in hex!
    // static key for now

    let key: [u8; 32] = [
        0x60, 0x1F, 0x5C, 0x9A, 0x3A, 0x2D, 0x72, 0xC9, 0xA4, 0xB7, 0x8C, 0xF9, 0xC8, 0x5A, 0x7D,
        0x56, 0x67, 0x29, 0xF1, 0x9E, 0xE4, 0x6A, 0x87, 0x11, 0xD2, 0x3E, 0x9B, 0xB1, 0x42, 0xF3,
        0x81, 0xF7,
    ];

    let mut aes256ctrcipher = aes256ctrbench::AES256Ctr::new(key, nonce);

    let encrypted_data = aes256ctrcipher.encrypt(plaintext_bytes);

    let decrypted_data = aes256ctrcipher.decrypt(&encrypted_data);
    match String::from_utf8(decrypted_data) {
        Ok(string) => {
            println!("Converted String: {}", string);
        }
        Err(e) => {
            println!("Error converting bytes to String: {}", e);
        }
    }
}
