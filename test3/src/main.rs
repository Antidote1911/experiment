use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use age::{Encryptor, Decryptor};
use age::secrecy::SecretString;

const ENCRYPTED_FILE: &str = "encrypted.bin";
const DECRYPTED_FILE: &str = "decrypted.mp4";

const CHUNK_SIZE: usize = 4096;

fn encrypt_file(input_file: &str, passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let input = File::open(input_file)?;
    let mut reader = BufReader::new(input);


    let encryptor = Encryptor::with_user_passphrase(SecretString::from(passphrase.to_string()));
    let encrypted_output = File::create(ENCRYPTED_FILE)?;
    let mut writer = encryptor.wrap_output(BufWriter::new(encrypted_output))?;

    let mut buffer = [0u8; CHUNK_SIZE];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buffer[..bytes_read])?;
    }
    writer.finish()?;

    Ok(())
}

fn decrypt_file(passphrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted_input = File::open(ENCRYPTED_FILE)?;
    let decryptor = Decryptor::new(encrypted_input)?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase));

    let mut reader = decryptor.decrypt(Some(&identity as _).into_iter())?;
    let mut output = BufWriter::new(File::create(DECRYPTED_FILE)?);

    let mut buffer = [0u8; CHUNK_SIZE];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        output.write_all(&buffer[..bytes_read])?;
    }

    Ok(())
}

fn main() {
    let input_file = "5.mp4";
    let passphrase = "super_secret_passphrase";

    match encrypt_file(input_file, passphrase) {
        Ok(_) => println!("File encrypted successfully."),
        Err(e) => eprintln!("Error encrypting file: {}", e),
    }

    match decrypt_file(passphrase) {
        Ok(_) => println!("File decrypted successfully."),
        Err(e) => eprintln!("Error decrypting file: {}", e),
    }
}