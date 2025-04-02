use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

const KEY: &[u8; 32] = b"an example very very secret key.";
const NONCE: &[u8; 24] = b"unique nonce goes here!!";

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

fn encrypt_file<P: AsRef<Path>>(input_path: P, output_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let key = aead::Key::<XChaCha20Poly1305>::from_slice(KEY);
    let cipher = XChaCha20Poly1305::new(key);

    let nonce = XNonce::from_slice(NONCE);

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    while let Ok(read_bytes) = input_file.read(&mut buffer) {
        if read_bytes == 0 {
            break;
        }

        let encrypted_chunk = cipher.encrypt(nonce, Payload {
            msg: &buffer[..read_bytes],
            aad: b"",
        });

        output_file.write_all(&encrypted_chunk.unwrap())?;
    }

    Ok(())
}

fn decrypt_file<P: AsRef<Path>>(input_path: P, output_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let key = aead::Key::<XChaCha20Poly1305>::from_slice(KEY);
    let cipher = XChaCha20Poly1305::new(key);

    let nonce = XNonce::from_slice(NONCE);

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut buffer = [0u8; CHUNK_SIZE + 16]; // CHUNK_SIZE bytes data + 16 bytes tag
    while let Ok(read_bytes) = input_file.read(&mut buffer) {
        if read_bytes == 0 {
            break;
        }

        let decrypted_chunk = cipher.decrypt(nonce, Payload {
            msg: &buffer[..read_bytes],
            aad: b"",
        });

        output_file.write_all(&decrypted_chunk.unwrap())?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let input_path = "5.mp4";
    let encrypted_path = "5.bin";
    let decrypted_path = "decrypted.mp4";

    encrypt_file(input_path, encrypted_path).expect("Encryption failed");
    decrypt_file(encrypted_path, decrypted_path).expect("Decryption failed");

    Ok(())
}
