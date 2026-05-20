//! Test-only helpers that build a synthetic console wallet SQLite database
//! shaped exactly like the one the legacy `tari_wallet` crate produces, so the
//! migration code can be exercised end-to-end without depending on the
//! console wallet binary.
//!
//! The encryption parameters and storage layout exactly mirror the live
//! console wallet at the time of writing — if the upstream wallet ever
//! changes its on-disk encryption format, these helpers must be updated in
//! lockstep with `console_db.rs`.

use std::path::Path;

use anyhow::{Context, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b, Digest};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::RngCore;
use rusqlite::{Connection, params};
use tari_common_types::seeds::cipher_seed::CipherSeed;
use tari_crypto::{hash_domain, hashing::DomainSeparatedHasher};
use tari_utilities::hex::Hex;

// Same domain identifier the runtime decrypt path uses; redeclared here so
// this module is self-contained for tests that don't import the live one.
hash_domain!(SecondaryKeyDomain, "com.tari.base_layer.wallet.secondary_key", 0);

const ARGON2_OUTPUT_LEN: usize = 32;
const SUPPORTED_ARGON2_VERSION: u8 = 1;
const MAIN_KEY_AAD_PREFIX: &[u8] = b"wallet_main_key_encryption_v";
const MASTER_SEED_AAD: &[u8] = b"wallet_setting_master_seed";

pub struct ConsoleFixtureBuilder {
    pub seed: CipherSeed,
    pub passphrase: String,
}

pub struct ConsoleFixture {
    pub db_path: std::path::PathBuf,
    pub passphrase: String,
}

impl ConsoleFixtureBuilder {
    pub fn new(passphrase: &str) -> Self {
        Self {
            seed: CipherSeed::random(),
            passphrase: passphrase.to_string(),
        }
    }

    pub fn write(self, dir: &Path) -> Result<ConsoleFixture, anyhow::Error> {
        let db_path = dir.join("console_wallet.sqlite3");
        let conn = Connection::open(&db_path).context("open synthetic console DB")?;

        create_console_schema(&conn)?;
        seed_encryption_settings(&conn, &self.seed, &self.passphrase)?;

        Ok(ConsoleFixture {
            db_path,
            passphrase: self.passphrase,
        })
    }
}

/// Insert a stub `completed_transactions` row with a known `tx_id` so the
/// migration can be observed to copy the ID through.
pub fn insert_test_completed_transaction(
    db_path: &Path,
    tx_id: u64,
    amount: u64,
    fee: u64,
    direction: i32,
    status: i32,
    mined_height: Option<u64>,
) -> Result<(), anyhow::Error> {
    let conn = Connection::open(db_path).context("reopen synthetic console DB")?;
    let now = chrono::Utc::now().naive_utc();
    conn.execute(
        "INSERT INTO completed_transactions (
            tx_id, source_address, destination_address, amount, fee,
            transaction_protocol, status, timestamp, cancelled, direction,
            send_count, last_send_timestamp, confirmations, mined_height,
            mined_in_block, mined_timestamp, transaction_signature_nonce,
            transaction_signature_key, payment_id, sent_output_hashes,
            received_output_hashes, change_output_hashes, user_payment_id,
            lock_height
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            0, NULL, NULL, ?11, NULL, ?12, ?13, ?14, NULL, NULL, NULL, NULL, NULL, 0
        )",
        params![
            tx_id as i64,
            vec![0u8; 35], // dummy source_address bytes (the migrator handles parse failures gracefully)
            vec![0u8; 35], // dummy destination_address
            amount as i64,
            fee as i64,
            Vec::<u8>::new(), // transaction_protocol blob
            status,
            now,
            None::<i32>, // cancelled
            direction,
            mined_height.map(|h| h as i64),
            now,           // mined_timestamp
            vec![0u8; 32], // transaction_signature_nonce
            vec![0u8; 32], // transaction_signature_key
        ],
    )?;
    Ok(())
}

/// Insert a stub `scanned_blocks` row.
pub fn insert_test_scanned_block(db_path: &Path, height: u64, hash: &[u8]) -> Result<(), anyhow::Error> {
    let conn = Connection::open(db_path)?;
    let now = chrono::Utc::now().naive_utc();
    conn.execute(
        "INSERT INTO scanned_blocks (header_hash, height, num_outputs, amount, timestamp)
         VALUES (?1, ?2, NULL, NULL, ?3)",
        params![hash, height as i64, now],
    )?;
    Ok(())
}

fn create_console_schema(conn: &Connection) -> Result<(), anyhow::Error> {
    // We only need the subset of tables our migration touches. Everything
    // else the console wallet has (e.g. inbound_transactions) is irrelevant.
    conn.execute_batch(
        r#"
        CREATE TABLE wallet_settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);

        CREATE TABLE outputs (
            id INTEGER PRIMARY KEY NOT NULL,
            commitment BLOB NOT NULL,
            rangeproof BLOB NULL,
            spending_key TEXT NOT NULL,
            value BIGINT NOT NULL,
            output_type INTEGER NOT NULL,
            maturity BIGINT NOT NULL,
            status INTEGER NOT NULL,
            hash BLOB NOT NULL,
            script BLOB NOT NULL,
            input_data BLOB NOT NULL,
            script_private_key TEXT NOT NULL,
            script_lock_height UNSIGNED BIGINT NOT NULL DEFAULT 0,
            sender_offset_public_key BLOB NOT NULL,
            metadata_signature_ephemeral_commitment BLOB NOT NULL,
            metadata_signature_ephemeral_pubkey BLOB NOT NULL,
            metadata_signature_u_a BLOB NOT NULL,
            metadata_signature_u_x BLOB NOT NULL,
            metadata_signature_u_y BLOB NOT NULL,
            mined_height UNSIGNED BIGINT NULL,
            mined_in_block BLOB NULL,
            mined_mmr_position BIGINT NULL,
            marked_deleted_at_height BIGINT NULL,
            marked_deleted_in_block BLOB NULL,
            received_in_tx_id BIGINT NULL,
            spent_in_tx_id BIGINT NULL,
            coinbase_block_height UNSIGNED BIGINT NULL,
            coinbase_extra BLOB NULL,
            features_json TEXT NOT NULL DEFAULT '{}',
            spending_priority UNSIGNED INTEGER NOT NULL DEFAULT 500,
            covenant BLOB NOT NULL,
            mined_timestamp DATETIME NULL,
            encrypted_data BLOB NOT NULL,
            minimum_value_promise BIGINT NOT NULL,
            source INTEGER NOT NULL DEFAULT 0,
            last_validation_timestamp DATETIME NULL,
            payment_id BLOB NULL,
            user_payment_id BLOB NULL,
            CONSTRAINT unique_commitment UNIQUE (commitment)
        );

        CREATE TABLE completed_transactions (
            tx_id BIGINT PRIMARY KEY NOT NULL,
            source_address BLOB NOT NULL,
            destination_address BLOB NOT NULL,
            amount BIGINT NOT NULL,
            fee BIGINT NOT NULL,
            transaction_protocol BLOB NOT NULL,
            status INTEGER NOT NULL,
            timestamp DATETIME NOT NULL,
            cancelled INTEGER NULL,
            direction INTEGER NULL,
            send_count INTEGER DEFAULT 0 NOT NULL,
            last_send_timestamp DATETIME NULL,
            confirmations BIGINT NULL,
            mined_height BIGINT NULL,
            mined_in_block BLOB NULL,
            mined_timestamp DATETIME NULL,
            transaction_signature_nonce BLOB NOT NULL DEFAULT 0,
            transaction_signature_key BLOB NOT NULL DEFAULT 0,
            payment_id BLOB NULL,
            sent_output_hashes BLOB NULL,
            received_output_hashes BLOB NULL,
            change_output_hashes BLOB NULL,
            user_payment_id BLOB NULL,
            lock_height BIGINT NULL DEFAULT 0
        );

        CREATE TABLE scanned_blocks (
            header_hash BLOB PRIMARY KEY NOT NULL,
            height BIGINT NOT NULL,
            num_outputs BIGINT NULL,
            amount BIGINT NULL,
            timestamp DATETIME NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn seed_encryption_settings(conn: &Connection, seed: &CipherSeed, passphrase: &str) -> Result<(), anyhow::Error> {
    // 1. Derive Argon2id-output, then secondary key/hash from it.
    let salt = generate_salt_string();
    let mut secondary_derivation_key = [0u8; ARGON2_OUTPUT_LEN];
    let argon2_params =
        Params::new(46 * 1024, 1, 1, Some(ARGON2_OUTPUT_LEN)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut secondary_derivation_key)
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;

    let secondary_key_bytes = DomainSeparatedHasher::<Blake2b<digest::consts::U32>, SecondaryKeyDomain>::new()
        .chain_update(secondary_derivation_key)
        .finalize();
    let secondary_key_array: [u8; 32] = secondary_key_bytes
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("secondary key length"))?;
    let secondary_key_hash_hex = hex::encode(secondary_key_array);

    // 2. Generate a fresh main key, encrypt under the secondary key.
    let mut main_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut main_key);

    let mut aad = MAIN_KEY_AAD_PREFIX.to_vec();
    aad.push(SUPPORTED_ARGON2_VERSION);

    let secondary_cipher = XChaCha20Poly1305::new(&Key::from(secondary_key_array));
    let encrypted_main_key = encrypt_integral_nonce(&secondary_cipher, &aad, &main_key)?;

    // 3. Encrypt the master seed bytes under the main key.
    let main_cipher = XChaCha20Poly1305::new(&Key::from(main_key));
    let seed_bytes = seed
        .encipher(None)
        .map_err(|e| anyhow!("CipherSeed::encipher failed: {e}"))?;
    let encrypted_master_seed = encrypt_integral_nonce(&main_cipher, MASTER_SEED_AAD, &seed_bytes)?;

    // 4. Persist the four encryption settings + the encrypted seed.
    let entries: Vec<(&str, String)> = vec![
        ("SecondaryKeyVersion", SUPPORTED_ARGON2_VERSION.to_string()),
        ("SecondaryKeySalt", salt),
        ("SecondaryKeyHash", secondary_key_hash_hex),
        ("EncryptedMainKey", encrypted_main_key.to_hex()),
        ("MasterSeed", encrypted_master_seed.to_hex()),
        ("WalletBirthday", seed.birthday().to_string()),
    ];
    for (key, value) in entries {
        conn.execute(
            "INSERT OR REPLACE INTO wallet_settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
    }
    Ok(())
}

fn encrypt_integral_nonce(cipher: &XChaCha20Poly1305, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let mut out = nonce_bytes.to_vec();
    let mut ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow!("aead encrypt: {e}"))?;
    out.append(&mut ciphertext);
    Ok(out)
}

/// The console wallet stores the salt as the textual rendering of a
/// `SaltString` (PHC base64). The Argon2 derivation only ever sees `salt.as_bytes()`,
/// so any random text is fine here as long as it round-trips byte-for-byte.
fn generate_salt_string() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
