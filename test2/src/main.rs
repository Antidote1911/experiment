use aead::{Aead, Payload};

use chacha20poly1305::{
    aead::{stream, OsRng},
    XChaCha20Poly1305, XNonce, Key, KeyInit, AeadCore};

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use aead::consts::U19;
use aead::generic_array::GenericArray;
// The nonce size for *BE32 is 5-bytes smaller (32-bit counter + last block flag byte) than the 24-byte XChaCha20Poly1305 nonce so 24 - 5 = 19 bytes.
// You need to use GenericArray<u8, U19>.

const KEY: &[u8; 32] = b"an example very very secret key.";
const NONCE: &[u8; 19] = b"unique nonce goes h";

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

fn encrypt_file<P: AsRef<Path>>(input_path: P, output_path: P) -> Result<(), Box<dyn std::error::Error>> {

    //let key   : Key               = XChaCha20Poly1305::generate_key(&mut OsRng);
    //let nonce : XNonce            = XChaCha20Poly1305::generate_nonce(&mut OsRng);


    let key = aead::Key::<XChaCha20Poly1305>::from_slice(KEY);
    let cipher = XChaCha20Poly1305::new(key);

    //let nonce= XNonce::from_slice(NONCE);
    let test:GenericArray<u8, U19> = NONCE.clone().into();

    let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, &test);

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    while let Ok(read_bytes) = input_file.read(&mut buffer) {
        if read_bytes == 0 {
            break;
        }

        let encrypted_chunk = stream_encryptor.encrypt_next(Payload {
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

    let test:GenericArray<u8, U19> = NONCE.clone().into();
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, &test);

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut buffer = [0u8; CHUNK_SIZE + 16]; // CHUNK_SIZE bytes data + 16 bytes tag
    while let Ok(read_bytes) = input_file.read(&mut buffer) {
        if read_bytes == 0 {
            break;
        }

        let decrypted_chunk = stream_decryptor.decrypt_next(Payload {
            msg: &buffer[..read_bytes],
            aad: b"",
        });

        output_file.write_all(&decrypted_chunk.unwrap())?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let input_path = "test.txt";
    let encrypted_path = "test.bin";
    let decrypted_path = "decrypted.txt";

    encrypt_file(input_path, encrypted_path).expect("Encryption failed");
    decrypt_file(encrypted_path, decrypted_path).expect("Decryption failed");

    Ok(())
}
