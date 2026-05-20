//! Read-only access to a legacy Tari console wallet SQLite database.
//!
//! The console wallet (`tari_wallet` crate) uses Diesel and a particular schema
//! evolution. The migration only needs a small slice of that schema, so this
//! module re-implements the few read paths it requires using `rusqlite`
//! directly. We intentionally avoid pulling in the full `tari_wallet` crate as
//! a dependency; the workspace minotari-cli is built against does not include
//! it and adding it would balloon the dependency footprint substantially.
//!
//! The trickiest piece is the cipher derivation. The console wallet stores the
//! master `CipherSeed` encrypted with a key derived from the user's passphrase
//! through this chain:
//!
//! ```text
//!     passphrase + salt --[Argon2id 46 MiB, 1 iter, 1 par, 32 byte]--> secondary_derivation_key
//!     secondary_derivation_key --[Blake2b-256, domain "com.tari.base_layer.wallet.secondary_key"]--> secondary_key
//!     XChaCha20Poly1305(secondary_key).decrypt(encrypted_main_key,
//!         AAD = b"wallet_main_key_encryption_v" + version_byte) -> main_key
//!     XChaCha20Poly1305(main_key).decrypt(encrypted_master_seed,
//!         AAD = b"wallet_setting_master_seed") -> CipherSeed bytes
//! ```
//!
//! The stored `secondary_key_hash` is itself the Blake2b-256 of the
//! Argon2id-derived material under the same domain; it doubles as a stored
//! "expected key" for password verification.
//!
//! Only Argon2 v1 (id = 1) is supported; the console wallet has had no other
//! versions to date.

use std::path::Path;

use anyhow::{Context, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b, Digest};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use tari_common_types::seeds::cipher_seed::CipherSeed;
use tari_crypto::{hash_domain, hashing::DomainSeparatedHasher};
use tari_utilities::hex::from_hex;
use zeroize::Zeroizing;

// Domain separator for the secondary key derivation. Must match the console
// wallet's `SecondaryKeyDomain` byte-for-byte.
hash_domain!(SecondaryKeyDomain, "com.tari.base_layer.wallet.secondary_key", 0);

// Argon2 parameters used by the console wallet's `Argon2Parameters::from_version(Some(1))`.
// These values are consensus-level — changing them breaks decryption of every
// existing console wallet.
const ARGON2_MEMORY_KIB: u32 = 46 * 1024;
const ARGON2_ITERATIONS: u32 = 1;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;
const SUPPORTED_ARGON2_VERSION: u8 = 1;

const MAIN_KEY_AAD_PREFIX: &[u8] = b"wallet_main_key_encryption_v";
const MASTER_SEED_AAD: &[u8] = b"wallet_setting_master_seed";

const XNONCE_SIZE: usize = 24;

/// Result of opening and authenticating against a legacy console wallet.
pub struct ConsoleWalletReader {
    conn: Connection,
}

/// One row from the source `outputs` table, as raw column bytes. Conversion
/// to a `WalletOutput` happens in `output_converter`.
#[derive(Debug, Clone)]
pub struct ConsoleOutputRow {
    pub commitment: Vec<u8>,
    pub spending_key: String,
    pub value: i64,
    pub output_type: i32,
    pub maturity: i64,
    pub status: i32,
    pub hash: Vec<u8>,
    pub script: Vec<u8>,
    pub input_data: Vec<u8>,
    pub script_private_key: String,
    pub script_lock_height: i64,
    pub sender_offset_public_key: Vec<u8>,
    pub metadata_signature_ephemeral_commitment: Vec<u8>,
    pub metadata_signature_ephemeral_pubkey: Vec<u8>,
    pub metadata_signature_u_a: Vec<u8>,
    pub metadata_signature_u_x: Vec<u8>,
    pub metadata_signature_u_y: Vec<u8>,
    pub mined_height: Option<i64>,
    pub mined_in_block: Option<Vec<u8>>,
    pub received_in_tx_id: Option<i64>,
    pub spent_in_tx_id: Option<i64>,
    pub features_json: String,
    pub covenant: Vec<u8>,
    pub mined_timestamp: Option<chrono::NaiveDateTime>,
    pub encrypted_data: Vec<u8>,
    pub minimum_value_promise: i64,
    pub payment_id: Option<Vec<u8>>,
    /// Canonical-bytes serialised `RangeProof`. Stored as `rangeproof` (one
    /// word) BLOB NULL on the source schema as of the 2023-06-20 migration.
    /// `None` is a legitimate value for outputs whose proof never made it
    /// into the source row (older imports, scanned-from-genesis under an
    /// earlier schema, etc.).
    pub rangeproof: Option<Vec<u8>>,
}

/// One row from the source `completed_transactions` table.
#[derive(Debug, Clone)]
pub struct ConsoleCompletedTxRow {
    pub tx_id: i64,
    pub source_address: Vec<u8>,
    pub destination_address: Vec<u8>,
    pub amount: i64,
    pub fee: i64,
    pub status: i32,
    pub timestamp: chrono::NaiveDateTime,
    pub cancelled: Option<i32>,
    pub direction: Option<i32>,
    pub mined_height: Option<i64>,
    pub mined_in_block: Option<Vec<u8>>,
    pub mined_timestamp: Option<chrono::NaiveDateTime>,
    pub payment_id: Option<Vec<u8>>,
    pub user_payment_id: Option<Vec<u8>>,
    pub sent_output_hashes: Option<Vec<u8>>,
    pub received_output_hashes: Option<Vec<u8>>,
    pub change_output_hashes: Option<Vec<u8>>,
}

/// Latest scanned block, for setting the new wallet's scan tip.
#[derive(Debug, Clone)]
pub struct ConsoleScannedTip {
    pub height: u64,
    pub header_hash: Vec<u8>,
}

impl ConsoleWalletReader {
    /// Opens the source database read-only and verifies the supplied passphrase
    /// by attempting to derive and authenticate the master key.
    pub fn open(path: &Path, passphrase: &str) -> Result<(Self, CipherSeed), anyhow::Error> {
        if !path.exists() {
            return Err(anyhow!("Console wallet database not found: {}", path.display()));
        }

        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
                .with_context(|| format!("Failed to open console wallet at {} (read-only)", path.display()))?;

        let reader = Self { conn };
        let cipher_seed = reader.derive_cipher_seed(passphrase)?;
        Ok((reader, cipher_seed))
    }

    fn read_setting(&self, key: &str) -> Result<Option<String>, anyhow::Error> {
        let result: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM wallet_settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    /// Reproduces the console wallet's secondary-key derivation and master-key
    /// decryption to produce the `XChaCha20Poly1305` cipher used to encrypt the
    /// master seed.
    fn derive_master_cipher(&self, passphrase: &str) -> Result<XChaCha20Poly1305, anyhow::Error> {
        let secondary_key_version = self
            .read_setting("SecondaryKeyVersion")?
            .ok_or_else(|| anyhow!("Console wallet is missing SecondaryKeyVersion (encryption never set up?)"))?;
        let secondary_key_salt = self
            .read_setting("SecondaryKeySalt")?
            .ok_or_else(|| anyhow!("Console wallet is missing SecondaryKeySalt"))?;
        let secondary_key_hash_hex = self
            .read_setting("SecondaryKeyHash")?
            .ok_or_else(|| anyhow!("Console wallet is missing SecondaryKeyHash"))?;
        let encrypted_main_key_hex = self
            .read_setting("EncryptedMainKey")?
            .ok_or_else(|| anyhow!("Console wallet is missing EncryptedMainKey"))?;

        let version: u8 = secondary_key_version
            .parse()
            .map_err(|e| anyhow!("Invalid SecondaryKeyVersion '{secondary_key_version}': {e}"))?;
        if version != SUPPORTED_ARGON2_VERSION {
            return Err(anyhow!(
                "Unsupported console wallet encryption version {version}; only version {SUPPORTED_ARGON2_VERSION} is supported"
            ));
        }

        let secondary_key_hash =
            from_hex(&secondary_key_hash_hex).map_err(|e| anyhow!("SecondaryKeyHash is not valid hex: {e}"))?;
        let encrypted_main_key =
            from_hex(&encrypted_main_key_hex).map_err(|e| anyhow!("EncryptedMainKey is not valid hex: {e}"))?;

        // 1. Argon2id over (passphrase, salt) — exactly the parameters the
        //    console wallet uses. Anything else fails the hash-commitment check
        //    on the next line.
        let mut secondary_derivation_key = Zeroizing::new([0u8; ARGON2_OUTPUT_LEN]);
        let argon2_params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|e| anyhow!("Failed to construct Argon2 parameters: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
        argon2
            .hash_password_into(
                passphrase.as_bytes(),
                secondary_key_salt.as_bytes(),
                secondary_derivation_key.as_mut(),
            )
            .map_err(|e| anyhow!("Argon2 derivation failed: {e}"))?;

        // 2. Blake2b-256 with the SecondaryKeyDomain to produce the secondary
        //    encryption key. The console wallet uses the *same* Blake2b output
        //    as both the secondary_key and the secondary_key_hash, so we can
        //    verify the password by comparing the derived value against the
        //    stored hash before attempting AEAD decryption.
        let secondary_key_bytes = DomainSeparatedHasher::<Blake2b<digest::consts::U32>, SecondaryKeyDomain>::new()
            .chain_update(secondary_derivation_key.as_ref())
            .finalize();
        let secondary_key_bytes = secondary_key_bytes.as_ref();

        if secondary_key_bytes != secondary_key_hash.as_slice() {
            return Err(anyhow!("Console wallet password is incorrect"));
        }

        // 3. AEAD-decrypt the main key under the secondary key. AAD is the
        //    domain prefix concatenated with the version byte.
        let mut aad = MAIN_KEY_AAD_PREFIX.to_vec();
        aad.push(version);
        let secondary_key_array: [u8; 32] = secondary_key_bytes
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| anyhow!("Secondary key has unexpected length: {e}"))?;
        let secondary_cipher = XChaCha20Poly1305::new(&Key::from(secondary_key_array));
        let main_key_bytes = decrypt_integral_nonce(&secondary_cipher, &aad, &encrypted_main_key)
            .map_err(|e| anyhow!("Main-key decryption failed: {e}"))?;
        if main_key_bytes.len() != 32 {
            return Err(anyhow!(
                "Decrypted main key has unexpected length {}",
                main_key_bytes.len()
            ));
        }

        // 4. The main key drives the cipher for everything else stored under
        //    `wallet_settings` (master seed, etc.).
        let main_key_array: [u8; 32] = main_key_bytes.as_slice().try_into().expect("length checked above");
        Ok(XChaCha20Poly1305::new(&Key::from(main_key_array)))
    }

    fn derive_cipher_seed(&self, passphrase: &str) -> Result<CipherSeed, anyhow::Error> {
        let cipher = self.derive_master_cipher(passphrase)?;

        let seed_hex = self
            .read_setting("MasterSeed")?
            .ok_or_else(|| anyhow!("Console wallet has no MasterSeed setting"))?;
        let seed_ciphertext = from_hex(&seed_hex).map_err(|e| anyhow!("MasterSeed is not valid hex: {e}"))?;

        let seed_bytes = decrypt_integral_nonce(&cipher, MASTER_SEED_AAD, &seed_ciphertext)
            .map_err(|e| anyhow!("Master seed decryption failed: {e}"))?;

        CipherSeed::from_enciphered_bytes(&seed_bytes, None)
            .map_err(|e| anyhow!("Failed to reconstruct CipherSeed from decrypted bytes: {e}"))
    }

    /// Returns every row from the source `outputs` table, in insertion order.
    pub fn read_outputs(&self) -> Result<Vec<ConsoleOutputRow>, anyhow::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT commitment, spending_key, value, output_type, maturity, status, hash, \
                    script, input_data, script_private_key, script_lock_height, sender_offset_public_key, \
                    metadata_signature_ephemeral_commitment, metadata_signature_ephemeral_pubkey, \
                    metadata_signature_u_a, metadata_signature_u_x, metadata_signature_u_y, \
                    mined_height, mined_in_block, received_in_tx_id, spent_in_tx_id, \
                    features_json, covenant, mined_timestamp, encrypted_data, minimum_value_promise, \
                    payment_id, rangeproof \
             FROM outputs \
             ORDER BY id ASC",
        )?;

        let rows = stmt
            .query_map([], |row| {
                Ok(ConsoleOutputRow {
                    commitment: row.get(0)?,
                    spending_key: row.get(1)?,
                    value: row.get(2)?,
                    output_type: row.get(3)?,
                    maturity: row.get(4)?,
                    status: row.get(5)?,
                    hash: row.get(6)?,
                    script: row.get(7)?,
                    input_data: row.get(8)?,
                    script_private_key: row.get(9)?,
                    script_lock_height: row.get(10)?,
                    sender_offset_public_key: row.get(11)?,
                    metadata_signature_ephemeral_commitment: row.get(12)?,
                    metadata_signature_ephemeral_pubkey: row.get(13)?,
                    metadata_signature_u_a: row.get(14)?,
                    metadata_signature_u_x: row.get(15)?,
                    metadata_signature_u_y: row.get(16)?,
                    mined_height: row.get(17)?,
                    mined_in_block: row.get(18)?,
                    received_in_tx_id: row.get(19)?,
                    spent_in_tx_id: row.get(20)?,
                    features_json: row.get(21)?,
                    covenant: row.get(22)?,
                    mined_timestamp: row.get(23)?,
                    encrypted_data: row.get(24)?,
                    minimum_value_promise: row.get(25)?,
                    payment_id: row.get(26)?,
                    rangeproof: row.get(27)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns every row from the source `completed_transactions` table.
    /// Cancelled rows are excluded — they would only confuse the new wallet's
    /// transaction history view.
    pub fn read_completed_transactions(&self) -> Result<Vec<ConsoleCompletedTxRow>, anyhow::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT tx_id, source_address, destination_address, amount, fee, \
                    status, timestamp, cancelled, direction, mined_height, mined_in_block, \
                    mined_timestamp, payment_id, user_payment_id, \
                    sent_output_hashes, received_output_hashes, change_output_hashes \
             FROM completed_transactions \
             WHERE cancelled IS NULL OR cancelled = 0 \
             ORDER BY tx_id ASC",
        )?;

        let rows = stmt
            .query_map([], |row| {
                Ok(ConsoleCompletedTxRow {
                    tx_id: row.get(0)?,
                    source_address: row.get(1)?,
                    destination_address: row.get(2)?,
                    amount: row.get(3)?,
                    fee: row.get(4)?,
                    status: row.get(5)?,
                    timestamp: row.get(6)?,
                    cancelled: row.get(7)?,
                    direction: row.get(8)?,
                    mined_height: row.get(9)?,
                    mined_in_block: row.get(10)?,
                    mined_timestamp: row.get(11)?,
                    payment_id: row.get(12)?,
                    user_payment_id: row.get(13)?,
                    sent_output_hashes: row.get(14)?,
                    received_output_hashes: row.get(15)?,
                    change_output_hashes: row.get(16)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns the highest-height entry from `scanned_blocks`, used to set the
    /// new wallet's scan tip so it does not repeat work the console wallet
    /// already did.
    pub fn read_latest_scanned_block(&self) -> Result<Option<ConsoleScannedTip>, anyhow::Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT header_hash, height FROM scanned_blocks ORDER BY height DESC LIMIT 1")?;

        let result = stmt
            .query_row([], |row| {
                let header_hash: Vec<u8> = row.get(0)?;
                let height: i64 = row.get(1)?;
                Ok(ConsoleScannedTip {
                    height: u64::try_from(height).unwrap_or(0),
                    header_hash,
                })
            })
            .optional()?;
        Ok(result)
    }
}

/// Decrypts a `nonce || ciphertext || tag` blob (the layout
/// `tari_common_types::encryption::encrypt_bytes_integral_nonce` produces).
///
/// We re-implement this rather than calling into `tari_common_types` because
/// minotari-cli pulls in `chacha20poly1305 0.11.0-rc.3` while the published
/// `tari_common_types` is built against `0.10.x` — the two versions of
/// `XChaCha20Poly1305` are distinct types and cannot be passed across the
/// crate boundary.
fn decrypt_integral_nonce(cipher: &XChaCha20Poly1305, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < XNONCE_SIZE {
        return Err(format!(
            "ciphertext too short: got {} bytes, need at least {}",
            blob.len(),
            XNONCE_SIZE
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(XNONCE_SIZE);
    let nonce_array: [u8; XNONCE_SIZE] = nonce_bytes
        .try_into()
        .map_err(|e: std::array::TryFromSliceError| format!("nonce slice conversion failed: {e}"))?;
    let nonce = XNonce::from(nonce_array);
    cipher
        .decrypt(&nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
        .map_err(|e| format!("AEAD decryption failed: {e}"))
}
