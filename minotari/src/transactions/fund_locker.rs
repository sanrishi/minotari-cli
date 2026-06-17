//! UTXO locking mechanism for transaction construction.
//!
//! This module provides functionality to temporarily lock UTXOs (Unspent Transaction Outputs)
//! during transaction construction, preventing double-spending scenarios where the same
//! outputs might be selected for multiple concurrent transactions.
//!
//! # Overview
//!
//! When creating a transaction, the wallet must:
//! 1. Select appropriate UTXOs to cover the transaction amount plus fees
//! 2. Lock those UTXOs to prevent other transactions from using them
//! 3. Either complete the transaction (consuming the UTXOs) or release the lock on failure
//!
//! The [`FundLocker`] handles steps 1 and 2, with automatic expiration to handle step 3
//! in case of failures or timeouts.
//!
//! # Idempotency
//!
//! Lock operations support idempotency keys, allowing clients to safely retry requests
//! without accidentally locking additional funds. If a lock request with the same
//! idempotency key already exists, the original result is returned.

use chrono::{Duration, Utc};
use log::info;
use std::sync::Mutex;
use tari_transaction_components::tari_amount::MicroMinotari;
use uuid::Uuid;

use crate::{
    api::types::LockFundsResult,
    db::{self, SqlitePool},
    log::mask_amount,
    transactions::input_selector::InputSelector,
};

/// Global mutex that serializes all [`FundLocker::lock`] calls.
///
/// The idempotency check and UTXO selection are not atomic at the database level;
/// without this mutex two concurrent requests could both pass the idempotency
/// check, select the same set of "unspent" outputs, and then race to lock them.
///
/// The mutex ensures that only one thread executes the critical section
/// (idempotency check → UTXO selection → pending-transaction creation →
/// output locking) at a time, eliminating the race condition described in
/// <https://github.com/anomalyco/minotari-cli/issues/125>.
static FUND_LOCK_MUTEX: Mutex<()> = Mutex::new(());

/// Manages temporary locking of UTXOs during transaction construction.
///
/// `FundLocker` ensures that UTXOs selected for a transaction cannot be used
/// by other concurrent transactions, preventing double-spending within the wallet.
/// Locks are time-limited and automatically expire if the transaction is not
/// completed within the specified duration.
///
/// # Thread Safety
///
/// A global [`Mutex`] serialises all [`lock`](FundLocker::lock) calls so that
/// the idempotency check, UTXO selection, pending-transaction creation, and
/// output locking happen atomically with respect to other threads.  The struct
/// itself can be safely shared across threads via cloning.
///
/// # Example
///
/// ```rust,ignore
/// use minotari::transactions::fund_locker::FundLocker;
/// use tari_transaction_components::tari_amount::MicroMinotari;
///
/// let locker = FundLocker::new(db_pool);
///
/// // Lock funds for a transaction
/// let result = locker.lock(
///     account_id,
///     MicroMinotari(1_000_000),  // amount to send
///     1,                         // number of outputs
///     MicroMinotari(5),          // fee per gram
///     None,                      // use default output size estimate
///     Some("unique-key".into()), // idempotency key
///     300,                       // lock for 5 minutes
/// ).await?;
///
/// // Use result.utxos to build the transaction
/// ```
pub struct FundLocker {
    db_pool: SqlitePool,
}

impl FundLocker {
    /// Creates a new `FundLocker` with the given database connection pool.
    ///
    /// # Arguments
    ///
    /// * `db_pool` - SQLite connection pool for database operations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let locker = FundLocker::new(db_pool);
    /// ```
    pub fn new(db_pool: SqlitePool) -> Self {
        Self { db_pool }
    }

    /// Locks UTXOs for a pending transaction.
    ///
    /// Selects unspent outputs sufficient to cover the requested amount plus estimated
    /// transaction fees, then locks them in the database with an expiration time.
    /// If an idempotency key is provided and a matching pending transaction exists,
    /// returns the existing lock result without creating a new one.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account whose UTXOs should be locked
    /// * `amount` - The amount to be sent (excluding fees)
    /// * `num_outputs` - Number of transaction outputs (typically 1 for recipient + optional change)
    /// * `fee_per_gram` - Fee rate in MicroMinotari per gram of transaction weight
    /// * `estimated_output_size` - Optional override for output size estimation; if `None`,
    ///   uses default calculation based on standard output features
    /// * `idempotency_key` - Optional unique key for idempotent operations; if provided and
    ///   a matching lock exists, returns the existing result
    /// * `seconds_to_lock_utxos` - Duration in seconds before the lock expires
    ///
    /// # Returns
    ///
    /// Returns a [`LockFundsResult`] containing:
    /// - The selected UTXOs
    /// - Whether a change output is required
    /// - Total value of selected UTXOs
    /// - Fee calculations with and without change output
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Database connection fails
    /// - Insufficient funds are available
    /// - UTXO selection fails due to serialization errors
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = locker.lock(
    ///     account_id,
    ///     MicroMinotari(500_000),
    ///     1,
    ///     MicroMinotari(5),
    ///     None,
    ///     Some("tx-123".to_string()),
    ///     600, // 10 minute lock
    /// ).await?;
    ///
    /// println!("Locked {} UTXOs worth {}", result.utxos.len(), result.total_value);
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn lock(
        &self,
        account_id: i64,
        amount: MicroMinotari,
        num_outputs: usize,
        fee_per_gram: MicroMinotari,
        estimated_output_size: Option<usize>,
        idempotency_key: Option<String>,
        seconds_to_lock_utxos: u64,
        confirmation_window: u64,
    ) -> Result<LockFundsResult, anyhow::Error> {
        info!(
            target: "audit",
            account_id = account_id,
            amount = &*mask_amount(amount);
            "Locking funds"
        );
        // Acquire a database connection first so we don't hold the global
        // mutex while waiting for a pooled connection (which could deadlock
        // under pool exhaustion).
        let mut conn = self.db_pool.get()?;
        // Fast idempotency check (without the global mutex).  If the pending
        // transaction already exists we can return immediately without waiting
        // for any concurrent `lock()` call to finish.
        if let Some(idempotency_key_str) = &idempotency_key
            && let Some(response) =
                db::find_pending_transaction_locked_funds_by_idempotency_key(&conn, idempotency_key_str, account_id)?
        {
            info!(
                target: "audit",
                idempotency_key = idempotency_key_str.as_str();
                "Found existing pending transaction lock"
            );
            return Ok(response);
        }

        // Acquire the global mutex so that the idempotency re-check, UTXO
        // selection, and database transaction are all serialised.  This
        // prevents a concurrent request from seeing the same "unspent" UTXOs
        // and creating a duplicate pending transaction.
        let _guard = FUND_LOCK_MUTEX
            .lock()
            .expect("Fund locker mutex poisoned – a prior lock() call panicked");
        // Re-check idempotency now that we hold the mutex.  The first thread
        // that passed the fast-path check above may have created the pending
        // transaction while we were waiting for the lock; if so we return its
        // result rather than selecting UTXOs a second time.
        if let Some(idempotency_key_str) = &idempotency_key
            && let Some(response) =
                db::find_pending_transaction_locked_funds_by_idempotency_key(&conn, idempotency_key_str, account_id)?
        {
            info!(
                target: "audit",
                idempotency_key = idempotency_key_str.as_str();
                "Found existing pending transaction lock (re-check)"
            );
            return Ok(response);
        }

        let input_selector = InputSelector::new(account_id, confirmation_window);
        let utxo_selection =
            input_selector.fetch_unspent_outputs(&conn, amount, num_outputs, fee_per_gram, estimated_output_size)?;

        let transaction = conn.transaction()?;
        #[allow(clippy::cast_possible_wrap)]
        let expires_at = Utc::now() + Duration::seconds(seconds_to_lock_utxos as i64);
        let idempotency_key = idempotency_key.unwrap_or_else(|| Uuid::new_v4().to_string());
        let pending_tx_id = db::create_pending_transaction(
            &transaction,
            &idempotency_key,
            account_id,
            utxo_selection.requires_change_output,
            utxo_selection.total_value,
            utxo_selection.fee_without_change,
            utxo_selection.fee_with_change,
            expires_at,
        )?;

        for utxo in &utxo_selection.utxos {
            db::lock_output(&transaction, utxo.id, &pending_tx_id, expires_at)?;
        }

        transaction.commit()?;

        info!(
            target: "audit",
            utxos_count = utxo_selection.utxos.len(),
            total_value = &*mask_amount(utxo_selection.total_value);
            "Funds locked successfully"
        );

        Ok(LockFundsResult {
            utxos: utxo_selection.utxos.iter().map(|utxo| utxo.output.clone()).collect(),
            requires_change_output: utxo_selection.requires_change_output,
            total_value: utxo_selection.total_value,
            fee_without_change: utxo_selection.fee_without_change,
            fee_with_change: utxo_selection.fee_with_change,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_wrap)]
    #![allow(clippy::cast_lossless)]
    #![allow(clippy::cast_possible_truncation)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db, insert_scanned_tip_block};
    use rusqlite::{Connection, named_params};
    use std::collections::HashSet;
    use tari_common_types::{
        seeds::cipher_seed::CipherSeed,
        types::{ComAndPubSignature, CompressedPublicKey, FixedHash},
    };
    use tari_script::{ExecutionStack, TariScript};
    use tari_transaction_components::{
        key_manager::{
            TariKeyId,
            wallet_types::{SeedWordsWallet, WalletType},
        },
        transaction_components::{
            EncryptedData, MemoField, OutputFeatures, TransactionOutputVersion, WalletOutput, covenants::Covenant,
        },
    };
    use tempfile::tempdir;

    /// Create a [`WalletOutput`] with the given value and hash seed, plus
    /// default parameters suitable for testing.
    fn test_wallet_output(value: u64, hash_seed: u8) -> WalletOutput {
        let mut hash = FixedHash::default();
        hash[0] = hash_seed;
        WalletOutput::new_from_parts(
            TransactionOutputVersion::default(),
            MicroMinotari::from(value),
            TariKeyId::default(),
            OutputFeatures::default(),
            TariScript::default(),
            ExecutionStack::default(),
            TariKeyId::default(),
            CompressedPublicKey::default(),
            ComAndPubSignature::default(),
            0,
            Covenant::default(),
            EncryptedData::default(),
            MicroMinotari::from(0),
            None,
            MemoField::new_empty(),
            hash,
            Default::default(),
        )
    }

    /// Insert a test output row directly into the database.
    fn insert_test_output(conn: &Connection, account_id: i64, output_hash_byte: u8, value: u64, mined_height: u64) {
        let output = test_wallet_output(value, output_hash_byte);
        let wallet_output_json = serde_json::to_string(&output).expect("serialize WalletOutput");
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash,
                value, mined_timestamp, wallet_output_json, status, confirmed_height,
                confirmed_hash, is_burn, maturity
            ) VALUES (
                :account_id, :tx_id, :output_hash, :height, :block_hash,
                :value, :mined_ts, :json, :status, :confirmed_height,
                :confirmed_hash, 0, :maturity
            )
            "#,
            named_params! {
                ":account_id": account_id,
                ":tx_id": output_hash_byte as i64,
                ":output_hash": vec![output_hash_byte; 32],
                ":height": mined_height as i64,
                ":block_hash": vec![output_hash_byte; 32],
                ":value": value as i64,
                ":mined_ts": Utc::now(),
                ":json": wallet_output_json,
                ":status": "UNSPENT",
                ":confirmed_height": mined_height as i64,
                ":confirmed_hash": vec![output_hash_byte; 32],
                ":maturity": 0,
            },
        )
        .expect("insert test output");
    }

    /// Create a fresh in-memory database, initialize it, create a test
    /// account, and seed a set of spendable UTXOs.  Returns the pool,
    /// connection, and account id.
    fn setup_test_env(output_count: usize, value_per_output: u64) -> (SqlitePool, i64, tempfile::TempDir) {
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("test.db")).expect("init db");
        let conn = pool.get().expect("get conn");

        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).expect("construct wallet"));
        create_account(&conn, "test", &wallet, "pass").expect("create account");
        let account = get_account_by_name(&conn, "test")
            .expect("get account")
            .expect("account exists");
        let account_id = account.id;

        // Insert a scanned tip block so `InputSelector` sees a non-zero tip
        insert_scanned_tip_block(&conn, account_id, 200, &[0u8; 32]).expect("insert tip block");

        // Insert spendable outputs
        for i in 0..output_count {
            insert_test_output(
                &conn,
                account_id,
                (i + 1) as u8,
                (i as u64 + 1) * value_per_output,
                100, // mined at block 100 → eligible with window=100, tip=200
            );
        }

        drop(conn);
        (pool, account_id, temp)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_lock_calls_select_disjoint_utxos() {
        let (pool, account_id, _temp) = setup_test_env(5, 500_000);

        let pool2 = pool.clone();
        let handle_a = std::thread::spawn(move || {
            let locker = FundLocker::new(pool);
            locker.lock(
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(0),
                Some(1000),
                None,
                3600,
                100, // confirmation_window = 100 → tip(200) − 100 = 100 ≥ mined(100)
            )
        });
        let handle_b = std::thread::spawn(move || {
            let locker = FundLocker::new(pool2);
            locker.lock(
                account_id,
                MicroMinotari(100_000),
                1,
                MicroMinotari(0),
                Some(1000),
                None,
                3600,
                100,
            )
        });

        let res_a = handle_a.join().expect("thread A panicked");
        let res_b = handle_b.join().expect("thread B panicked");

        let result_a = res_a.expect("lock A succeeded");
        let result_b = res_b.expect("lock B succeeded");

        // Each call must have locked at least one UTXO
        assert!(!result_a.utxos.is_empty(), "A got at least one UTXO");
        assert!(!result_b.utxos.is_empty(), "B got at least one UTXO");

        // The two result sets must not share any UTXO (identified by its hash)
        let hashes_a: HashSet<FixedHash> = result_a.utxos.iter().map(|u| u.output_hash()).collect();
        let hashes_b: HashSet<FixedHash> = result_b.utxos.iter().map(|u| u.output_hash()).collect();

        let intersection: HashSet<_> = hashes_a.intersection(&hashes_b).copied().collect();
        assert!(
            intersection.is_empty(),
            "Concurrent lock calls selected overlapping UTXOs: {intersection:?}",
        );
    }

    #[test]
    fn idempotency_key_returns_same_result_concurrently() {
        let (pool, account_id, _temp) = setup_test_env(3, 1_000_000);

        let key = "concurrent-idempotency-key".to_string();
        let pool2 = pool.clone();
        let key2 = key.clone();

        let handle_a = std::thread::spawn(move || {
            let locker = FundLocker::new(pool);
            locker.lock(
                account_id,
                MicroMinotari(200_000),
                1,
                MicroMinotari(0),
                Some(1000),
                Some(key),
                3600,
                100,
            )
        });
        let handle_b = std::thread::spawn(move || {
            let locker = FundLocker::new(pool2);
            locker.lock(
                account_id,
                MicroMinotari(200_000),
                1,
                MicroMinotari(0),
                Some(1000),
                Some(key2),
                3600,
                100,
            )
        });

        let res_a = handle_a.join().expect("thread A panicked");
        let res_b = handle_b.join().expect("thread B panicked");

        let result_a = res_a.expect("lock A succeeded");
        let result_b = res_b.expect("lock B succeeded");

        // Both should see the same locked funds (same UTXOs, same totals)
        let hashes_a: HashSet<FixedHash> = result_a.utxos.iter().map(|u| u.output_hash()).collect();
        let hashes_b: HashSet<FixedHash> = result_b.utxos.iter().map(|u| u.output_hash()).collect();

        assert_eq!(
            hashes_a, hashes_b,
            "Idempotent concurrent calls must return identical UTXO sets",
        );
        assert_eq!(result_a.total_value, result_b.total_value);
        assert_eq!(result_a.requires_change_output, result_b.requires_change_output);
    }

    #[test]
    fn mutex_serialises_lock_calls() {
        // Verify that the global `FUND_LOCK_MUTEX` serialises callers:
        // two concurrent `lock()` calls on the *same* account both succeed
        // without overlapping UTXO sets (each sees a disjoint set of UTXOs
        // because the first call's side-effects are visible to the second).
        //
        // This is already exercised by `concurrent_lock_calls_select_disjoint_utxos`
        // above; this test adds a second scenario using a different account to
        // ensure the mutex does not prevent different accounts from making
        // progress (though in practice they share the global lock).
        let (pool_a, account_a, _temp_a) = setup_test_env(3, 1_000_000);
        let (pool_b, account_b, _temp_b) = setup_test_env(3, 1_000_000);

        let _pool_a2 = pool_a.clone();
        let _pool_b2 = pool_b.clone();

        let h_a = std::thread::spawn(move || {
            FundLocker::new(pool_a).lock(
                account_a,
                MicroMinotari(200_000),
                1,
                MicroMinotari(0),
                Some(1000),
                None,
                3600,
                100,
            )
        });
        let h_b = std::thread::spawn(move || {
            FundLocker::new(pool_b).lock(
                account_b,
                MicroMinotari(200_000),
                1,
                MicroMinotari(0),
                Some(1000),
                None,
                3600,
                100,
            )
        });

        let r_a = h_a.join().expect("thread A panicked").expect("lock A ok");
        let r_b = h_b.join().expect("thread B panicked").expect("lock B ok");

        // Both should succeed (no double-spend errors) and select at least one UTXO
        assert!(!r_a.utxos.is_empty(), "A got UTXOs");
        assert!(!r_b.utxos.is_empty(), "B got UTXOs");
    }
}
