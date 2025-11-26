use anyhow::Result;
use aes_gcm::Aes256Gcm;
use aes_gcm::{KeyInit, aead::Aead};
use rand::RngCore;

pub struct KDSession {
    aes: Aes256Gcm,
}

impl KDSession {
    pub fn new(shared_secret: &[u8]) -> Self {
        let key = if shared_secret.len() >= 32 {
            &shared_secret[..32]
        } else {
            panic!("Shared secret too short for AES-256");
        };
        let aes = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
        Self { aes }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let ct = self.aes.encrypt(&nonce.into(), plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        
        let mut out = nonce.to_vec();
        out.extend(ct);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Data too short"));
        }
        
        let (nonce, ct) = data.split_at(12);
        let pt = self.aes.decrypt(nonce.into(), ct)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        Ok(pt)
    }
}