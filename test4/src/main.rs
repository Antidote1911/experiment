use anyhow::anyhow;

use chacha20poly1305::{
    aead::{stream},
    XChaCha20Poly1305, Key, KeyInit};

use std::path::Path;

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};

use std::time::{SystemTime, UNIX_EPOCH};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use rand::{Rng};

use indicatif::ProgressBar;
use indicatif::ProgressStyle;

// The nonce size for *BE32 is 5-bytes smaller (32-bit counter + last block flag byte) than the 24-byte XChaCha20Poly1305 nonce so 24 - 5 = 19 bytes.
// You need to use GenericArray<u8, U19>.

// const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 19;
const SALT_SIZE: usize = 16;

const TAG_LEN: usize = 16;
const ENCRYPTION_CHUNK_SIZE: usize = 1024 * 512; // 1 MB

const BAR_TEMPLATE: &str = "{elapsed_precise:>8} | {binary_bytes_per_sec:<12} [{bar:40.red}] {bytes:>10} / {total_bytes:<10} {msg}";
const BAR_CHARS: &str = "=> ";

fn generate_salt() -> [u8; SALT_SIZE] {
    let salt: [u8; SALT_SIZE] = rand::rng().random();
    salt
}

fn generate_nonce() -> [u8; NONCE_SIZE] {
    let nonce: [u8; NONCE_SIZE] = rand::rng().random();
    nonce
}

fn encrypt_file<P: AsRef<Path>>(input_path: P, output_path: P, password: &str) -> Result<(), anyhow::Error>  {

    //let key   : Key               = XChaCha20Poly1305::generate_key(&mut OsRng);
    //let nonce : XNonce            = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let salt = generate_salt();
    let nonce= generate_nonce();

    let key= argon2_hash(password.into(),&salt)?;

    let cipher = XChaCha20Poly1305::new(&key);
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, &nonce.into());

    let input_file = File::open(input_path)?;
    let output_file = File::create(output_path)?;
    let bin_metadata = input_file.metadata()?;
    let bin_len = bin_metadata.len();
    let mut input_reader = BufReader::new(input_file);
    let mut output_writer = BufWriter::new(output_file);

    output_writer.write_all(&salt)?;
    output_writer.write_all(&nonce)?;

    let mut buffer = vec![0; ENCRYPTION_CHUNK_SIZE + TAG_LEN];
    let mut filled: usize = 0;

    let bar = ProgressBar::new(bin_len);
    bar.set_style(ProgressStyle::default_bar().template(BAR_TEMPLATE).progress_chars(BAR_CHARS));

    loop {
        let read_count = input_reader.read(&mut buffer[filled..ENCRYPTION_CHUNK_SIZE])?;
        filled += read_count;

        if filled == ENCRYPTION_CHUNK_SIZE {
            buffer.truncate(ENCRYPTION_CHUNK_SIZE);
            stream_encryptor.encrypt_next_in_place(&[], &mut buffer).map_err(|err| anyhow!("Encrypting error: {}", err))?;
            output_writer.write_all(&buffer)?;
            bar.inc(filled as u64);
            filled = 0;
        } else if read_count == 0 {
            buffer.truncate(filled);
            stream_encryptor.encrypt_last_in_place(&[], &mut buffer).map_err(|err| anyhow!("Encrypting error: {}", err))?;
            output_writer.write_all(&buffer)?;
            bar.inc(filled as u64);
            break;
        }
        output_writer.flush()?
    }
    bar.finish_and_clear();
    Ok(())
}
fn decrypt_file<P: AsRef<Path>>(input_path: P, output_path: P,password:&str) -> Result<(), anyhow::Error> {

    let input_file = File::open(input_path)?;
    let output_file = File::create(output_path)?;
    let metadata = input_file.metadata()?;
    let bin_len = metadata.len();
    let mut input_reader = BufReader::new(input_file);
    let mut output_writer = BufWriter::new(output_file);

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    input_reader.read_exact(&mut salt)?;
    input_reader.read_exact(&mut nonce)?;

    let derived_key = argon2_hash(password,&salt)?;

    let cipher = XChaCha20Poly1305::new(&derived_key);
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, &nonce.into());

    let mut buffer = vec![0u8; ENCRYPTION_CHUNK_SIZE + TAG_LEN];

    let mut filled = 0;

    let bar = ProgressBar::new(bin_len);
    bar.set_style(ProgressStyle::default_bar().template(BAR_TEMPLATE).progress_chars(BAR_CHARS));

    loop {
        let read_count = input_reader.read(&mut buffer[filled..])?;
        filled += read_count;

        if filled == ENCRYPTION_CHUNK_SIZE + TAG_LEN {
            stream_decryptor.decrypt_next_in_place(&[], &mut buffer).map_err(|err| anyhow!("Decrypting error: {}", err))?;
            output_writer.write_all(&buffer)?;
            buffer.resize(ENCRYPTION_CHUNK_SIZE + TAG_LEN, 0);
            bar.inc(filled as u64);
            filled = 0;
        } else if read_count == 0 {
            buffer.truncate(filled);
            stream_decryptor.decrypt_last_in_place(&[], &mut buffer).map_err(|err| anyhow!("Decrypting error: {}", err))?;
            output_writer.write_all(&buffer)?;
            bar.inc(filled as u64);
            break;
        }
        output_writer.flush()?
    }
    bar.finish_and_clear();
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
