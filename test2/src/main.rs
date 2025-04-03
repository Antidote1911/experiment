use aead::{Aead, Payload};

use chacha20poly1305::{
    aead::{stream, OsRng},
    XChaCha20Poly1305, XNonce, Key, KeyInit, AeadCore};

use std::path::Path;
use aead::consts::U19;
use aead::generic_array::GenericArray;

use std::fs::File;
use std::io::{self, Read, Write};

use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
// The nonce size for *BE32 is 5-bytes smaller (32-bit counter + last block flag byte) than the 24-byte XChaCha20Poly1305 nonce so 24 - 5 = 19 bytes.
// You need to use GenericArray<u8, U19>.

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 19;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB


fn encrypt_file<P: AsRef<Path>>(input_path: P, output_path: P,key:&[u8]) -> Result<(), Box<dyn std::error::Error>> {

    //let key   : Key               = XChaCha20Poly1305::generate_key(&mut OsRng);
    //let nonce : XNonce            = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let salt: [u8; SALT_SIZE] = rand::rng().random();
    let nonce: [u8; NONCE_SIZE] = rand::rng().random();

    //let nonce= XNonce::from_slice(NONCE);

    // create the stream encryptor
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, &nonce.into());

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    // write salt and nonce
    output_file.write_all(&salt)?;
    output_file.write_all(&nonce)?;

    let mut buffer = [0u8; CHUNK_SIZE];
    while let Ok(read_bytes) = input_file.read(&mut buffer){
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

fn decrypt_file<P: AsRef<Path>>(input_path: P, output_path: P,key:&[u8]) -> Result<(), Box<dyn std::error::Error>> {

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    input_file.read_exact(&mut salt)?;
    input_file.read_exact(&mut nonce)?;

    // create the stream decryptor
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce.into());

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
    let keyslice = b"an example very very secret key."; // 32 bytes
    let key = aead::Key::<XChaCha20Poly1305>::from_slice(keyslice);

    let input_path = "5.mp4";
    let encrypted_path = "5.bin";
    let decrypted_path = "decrypted.mp4";

    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    encrypt_file(input_path, encrypted_path,key).expect("Encryption failed");
    decrypt_file(encrypted_path, decrypted_path,key).expect("Decryption failed");
    let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let test=end-start;
    println!("Time elapsed: {} ms", test.as_millis());
    Ok(())
}
