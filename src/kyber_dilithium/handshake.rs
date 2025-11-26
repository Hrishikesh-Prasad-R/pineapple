use anyhow::{Result, anyhow};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct KDHandshakeData {
    pub dilithium_pk: Vec<u8>,
    pub kyber_pk: Vec<u8>,
    pub dilithium_sk: Vec<u8>,  // Add this so we can store it
    pub kyber_sk: Vec<u8>,       // Add this so we can store it
    pub signature: Vec<u8>,
}

pub fn kd_init_handshake(py: Python<'_>) -> Result<KDHandshakeData> {
    let kd = PyModule::import_bound(py, "kd_bridge")?;

    let dilithium = kd.getattr("Dilithium3")?.call0()?;
    let kyber = kd.getattr("Kyber768")?.call0()?;

    let dilithium_keys = dilithium.getattr("keypair")?.call0()?;
    let kyber_keys = kyber.getattr("keypair")?.call0()?;

    let dil_pk: Vec<u8> = dilithium_keys.get_item(0)?.extract()?;
    let dil_sk: Vec<u8> = dilithium_keys.get_item(1)?.extract()?;

    let kyb_pk: Vec<u8> = kyber_keys.get_item(0)?.extract()?;
    let kyb_sk: Vec<u8> = kyber_keys.get_item(1)?.extract()?;

    // Sign Kyber public key
    let sig: Vec<u8> = dilithium
        .getattr("sign")?
        .call1((kyb_pk.clone(), dil_sk.clone()))?
        .extract()?;

    Ok(KDHandshakeData {
        dilithium_pk: dil_pk,
        kyber_pk: kyb_pk,
        dilithium_sk: dil_sk,
        kyber_sk: kyb_sk,
        signature: sig,
    })
}

pub fn kd_process_handshake(
    py: Python<'_>,
    received: &KDHandshakeData
) -> Result<(Vec<u8>, Vec<u8>)> {
    let kd = PyModule::import_bound(py, "kd_bridge")?;
    let dilithium = kd.getattr("Dilithium3")?.call0()?;
    let kyber = kd.getattr("Kyber768")?.call0()?;

    // Verify signature
    let valid: bool = dilithium
        .getattr("verify")?
        .call1((
            received.signature.clone(),
            received.kyber_pk.clone(),
            received.dilithium_pk.clone()
        ))?
        .extract()?;

    if !valid {
        return Err(anyhow!("Dilithium signature invalid"));
    }

    // Encapsulate
    let result = kyber
        .getattr("encapsulate")?
        .call1((received.kyber_pk.clone(),))?;
    
    let ct: Vec<u8> = result.get_item(0)?.extract()?;
    let ss: Vec<u8> = result.get_item(1)?.extract()?;

    Ok((ct, ss))
}

pub fn kd_finish_handshake(
    py: Python<'_>,
    ciphertext: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>> {
    let kd = PyModule::import_bound(py, "kd_bridge")?;
    let kyber = kd.getattr("Kyber768")?.call0()?;

    let ss: Vec<u8> = kyber
        .getattr("decapsulate")?
        .call1((ciphertext, secret_key))?
        .extract()?;

    Ok(ss)
}