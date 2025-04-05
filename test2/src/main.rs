use anyhow::anyhow;
use aead::{Aead, Payload};

use chacha20poly1305::{
    aead::{stream},
    XChaCha20Poly1305, XNonce, Key, KeyInit, AeadCore};

use std::path::Path;
//use aead::consts::U19;
//use aead::generic_array::GenericArray;

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};

use std::time::{SystemTime, UNIX_EPOCH};
use argon2::{Algorithm, Argon2, Params, ParamsBuilder, Version};
use rand::Rng;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

// The nonce size for *BE32 is 5-bytes smaller (32-bit counter + last block flag byte) than the 24-byte XChaCha20Poly1305 nonce so 24 - 5 = 19 bytes.
// You need to use GenericArray<u8, U19>.

// const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 19;
const SALT_SIZE: usize = 16;

const TAG_LEN: usize = 16;
const ENCRYPTION_CHUNK_SIZE: usize = 1024 * 512; // 1 MB
const DECRYPTION_CHUNK_SIZE: usize = ENCRYPTION_CHUNK_SIZE + TAG_LEN;

fn encrypt_file<P: AsRef<Path>>(input_path: P, output_path: P, password: &str) -> Result<(), anyhow::Error>  {

    //let key   : Key               = XChaCha20Poly1305::generate_key(&mut OsRng);
    //let nonce : XNonce            = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let salt: [u8; SALT_SIZE] = rand::rng().random();
    let nonce: [u8; NONCE_SIZE] = rand::rng().random();

    let hexsalt= hex::encode_upper(salt);
    let hexnonce= hex::encode_upper(nonce);
    println!("Salt  {}: Hex:  {}", salt.len(),hexsalt);
    println!("Nonce {}: Hex:  {}", nonce.len(),hexnonce);

    let key= argon2_hash(password.into(),&salt)?;

    let hexkey= hex::encode_upper(key);
    println!("Key   {}: Hex:  {}", key.len(),hexkey);

    //let nonce= XNonce::from_slice(NONCE);

    // create the stream encryptor
    let cipher = XChaCha20Poly1305::new(&key);
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, &nonce.into());

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    // write salt and nonce
    output_file.write_all(&salt)?;
    output_file.write_all(&nonce)?;

    let mut buffer = [0u8; ENCRYPTION_CHUNK_SIZE];

    let metadata = input_file.metadata()?;
    let total_size = metadata.len();
    let progress_bar = ProgressBar::new(total_size);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));

    loop {
        let read_count = input_file.read(&mut buffer)?;

        if read_count == ENCRYPTION_CHUNK_SIZE {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting file: {}", err))?;
            output_file.write_all(&ciphertext)?;
            progress_bar.inc(read_count as u64);
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting file: {}", err))?;
            output_file.write_all(&ciphertext)?;
            progress_bar.inc(read_count as u64);
            break;
        }
    }
    progress_bar.finish_with_message("Encryption complete");
    Ok(())
}
fn decrypt_file<P: AsRef<Path>>(input_path: P, output_path: P,password:&str) -> Result<(), anyhow::Error> {

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    input_file.read_exact(&mut salt)?;
    input_file.read_exact(&mut nonce)?;

    let hexsalt= hex::encode_upper(salt);
    let hexnonce= hex::encode_upper(nonce);
    println!("Salt  {}: Hex:  {}", salt.len(),hexsalt);
    println!("Nonce {}: Hex:  {}", nonce.len(),hexnonce);

    let derived_key = argon2_hash(password,&salt)?;

    let hexkey= hex::encode_upper(derived_key);
    println!("Key   {}: Hex:  {}", derived_key.len(),hexkey);

    // create the stream decryptor
    let cipher = XChaCha20Poly1305::new(&derived_key);
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce.into());

    let mut buffer = [0u8; DECRYPTION_CHUNK_SIZE]; // CHUNK_SIZE bytes data + 16 bytes tag

    let metadata = input_file.metadata()?;
    let total_size = metadata.len();
    let progress_bar = ProgressBar::new(total_size);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));

    loop {
        let read_count = input_file.read(&mut buffer)?;

        if read_count == buffer.len() {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            output_file.write(&plaintext)?;
            progress_bar.inc(read_count as u64);
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            output_file.write(&plaintext)?;
            progress_bar.inc(read_count as u64);
            break;
        }
    }
    progress_bar.finish_with_message("Decryption complete");
    Ok(())
}

pub fn argon2_hash(
    password: &str,
    salt: &[u8; SALT_SIZE]
) -> Result<Key, anyhow::Error> {

    let mut builder = ParamsBuilder::new();
    builder.m_cost(1024 * 100);
    builder.t_cost(8);
    builder.p_cost(4);
    builder.output_len(32);

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, builder.build().unwrap());
    let mut keyarray = [0u8; 32];
    argon2.hash_password_into(password.as_ref(), salt, &mut keyarray).map_err(|err| anyhow!("Argon2 error: {}", err))?;
    let key = aead::Key::<XChaCha20Poly1305>::from(keyarray);
    Ok(key)
}

fn main() -> io::Result<()> {
    let password = "coucou!!";

    let input_path = "5.mp4";
    let encrypted_path = "5.bin";
    let decrypted_path = "decrypted.mp4";

    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    encrypt_file(input_path, encrypted_path,password).expect("Encryption failed");
    decrypt_file(encrypted_path, decrypted_path,password).expect("Decryption failed");
    let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let test=end-start;
    println!("Time elapsed: {} ms", test.as_millis());
    Ok(())
}
