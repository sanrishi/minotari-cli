//! Migration of an already-synced console wallet (legacy `tari` wallet) into
//! the minotari-cli database format.
//!
//! Closes [issue #119](https://github.com/tari-project/minotari-cli/issues/119).
//!
//! The motivation is that re-scanning the chain from the genesis block can
//! take hours on a busy node. Users coming from the legacy console wallet
//! already have a fully scanned local SQLite database; this module imports
//! that data directly so the migrated wallet can be used immediately, with
//! the same balance, the same UTXO set, and the same display transaction IDs
//! the user is accustomed to.
//!
//! # Pipeline
//!
//! 1. Open the source console wallet SQLite read-only.
//! 2. Derive the wallet cipher from the user-supplied password (Argon2id ->
//!    secondary key -> XChaCha20-Poly1305 main key).
//! 3. Decrypt the master `CipherSeed` from the `wallet_settings` table.
//! 4. Construct a fresh `SeedWordsWallet` from the seed and create a new
//!    minotari-cli account encrypted with the user-supplied minotari-cli
//!    password.
//! 5. Stream rows from the source `outputs` table, reconstruct each
//!    `WalletOutput` from its decomposed columns, and insert it into the
//!    minotari-cli `outputs` table preserving spent / unspent status.
//! 6. Stream rows from the source `completed_transactions` table, build the
//!    corresponding `DisplayedTransaction`, and insert it preserving the
//!    original `tx_id` value as the user-facing display id.
//! 7. Copy the source's last scanned block height/hash into the new
//!    `scanned_tip_blocks` table so the scanner resumes from there rather
//!    than re-scanning from genesis.
//!
//! # What the migration does NOT preserve
//!
//! * Pending / inbound / outbound transactions that never reached the
//!   `Completed` state in the console wallet. By design — the bounty
//!   acceptance criteria only requires completed transactions.
//! * Per-row encrypted blob entries (the console wallet does not encrypt
//!   output columns at rest, only the master seed setting).
//! * Cancelled transactions — they would only confuse the new wallet.

pub mod console_db;
pub mod migrator;
pub mod output_converter;
pub mod tx_converter;

#[cfg(test)]
mod test_fixture;

#[cfg(test)]
mod tests;

pub use migrator::{MigrationOptions, MigrationReport, run_migration};
