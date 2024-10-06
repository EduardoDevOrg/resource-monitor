use base64::{engine::general_purpose, Engine as _};
use openssl::rsa::Rsa;
use super::logging::agent_logger;

pub fn decrypt_password(password: &str) -> Option<String> {
    // Embedded public key in base64 format (including PEM headers)
    let public_key_base64 = include_str!("../../public_key.txt");

    // Decode the public key from base64
    let public_key_pem = match general_purpose::STANDARD.decode(public_key_base64) {
        Ok(pem) => pem,
        Err(_) => {
            agent_logger("error", "decrypt_password", 
            r#"{
                    "message": "Error decoding public key"
                    "module": "decryptor"
                }"#);
            return None;
        }
    };


    let public_key = match Rsa::public_key_from_pem(&public_key_pem) {
        Ok(key) => key,
        Err(_) => {
            agent_logger("error", "public_key_from_pem", 
            r#"{
                    "message": "Error retrieving public key"
                }"#);
            return None;
        }
    };


    // Decode the base64 data
    let encrypted_data = match general_purpose::STANDARD.decode(password) {
        Ok(data) => data,
        Err(_) => {
            agent_logger("error", "decode", 
            r#"{
                    "message": "Error decoding encrypted data"
                }"#);
            return None;
        }
    }; 

    // Prepare a buffer for decrypted data
    let mut decrypted_data = vec![0; public_key.size() as usize];

    // Decrypt the data
    match public_key.public_decrypt(
        &encrypted_data,
        &mut decrypted_data,
        openssl::rsa::Padding::PKCS1,
    ) {
        Ok(decrypted_size) => {
            // Truncate the buffer to the actual decrypted size
            decrypted_data.truncate(decrypted_size);

            // Convert decrypted data to string
            match String::from_utf8(decrypted_data) {
                Ok(verified_string) => Some(verified_string),
                Err(_) => {
                    agent_logger("error", "public_decrypt", 
                    r#"{
                            "message": "Error converting decrypted data to string"
                        }"#);
                    None
                }
            }
        }
        Err(_) => {
            agent_logger("error", "public_decrypt", 
            r#"{
                    "message": "Error decrypting data",
                }"#);
            None
        }
    }
}