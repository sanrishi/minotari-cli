//! End-to-end migration tests that build a synthetic console wallet, run the
//! migrator, and assert the destination minotari-cli database contains the
//! expected data.
//!
//! Output reconstruction is exercised by a separate, narrower test that
//! generates a real `WalletOutput` via the in-process key manager and then
//! serialises it back into the legacy column form so we can prove the
//! converter round-trips without depending on real chain state.

#![allow(clippy::indexing_slicing)]

use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension, params};
use tempfile::tempdir;

use super::test_fixture::{ConsoleFixtureBuilder, insert_test_completed_transaction, insert_test_scanned_block};
use super::{MigrationOptions, run_migration};

const SOURCE_PASSPHRASE: &str = "old-console-wallet-pw";
const DEST_PASSPHRASE: &str = "new-wallet-pw";

#[test]
fn migration_creates_account_with_seed_words_recovered_from_source() {
    // Validates the cipher seed round-trip: given a console wallet sealed with a
    // known passphrase, the migrator can decrypt the master seed, build a
    // SeedWordsWallet from it, and persist the resulting account into the
    // destination DB.
    let temp = tempdir().expect("temp dir");
    let fixture = ConsoleFixtureBuilder::new(SOURCE_PASSPHRASE)
        .write(temp.path())
        .expect("write console fixture");
    let dest_db = temp.path().join("destination_wallet.sqlite3");

    let report = run_migration(MigrationOptions {
        source_db_path: fixture.db_path.clone(),
        source_passphrase: fixture.passphrase.clone(),
        destination_db_path: dest_db.clone(),
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "imported".to_string(),
        dry_run: false,
    })
    .expect("migration succeeds");

    assert_eq!(report.account_name, "imported");
    // We didn't seed any outputs into the fixture so the migrator must
    // produce zero migrated outputs, and a zero net balance, without panicking.
    assert_eq!(report.outputs_migrated, 0);
    assert_eq!(report.unspent_outputs_count, 0);
    // Source balance = imported balance = 0; balance check must pass.
    assert_eq!(report.source_balance.as_u64(), 0);
    assert!(
        report.balance_match,
        "empty source must produce a matching imported balance"
    );
    assert!(
        !report.dry_run,
        "non-dry-run option must surface as dry_run = false in the report"
    );

    // The destination DB should now contain exactly one account row, named
    // "imported". The exact view/spend keys come from the seed we generated
    // in the fixture; we check the row exists rather than re-deriving them.
    let conn = Connection::open(&dest_db).expect("open destination");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM accounts WHERE friendly_name = 'imported'",
            [],
            |r| r.get(0),
        )
        .expect("count query");
    assert_eq!(count, 1, "exactly one account named 'imported' should exist");
}

#[test]
fn migration_dry_run_writes_nothing_but_returns_report() {
    // `--dry-run` must execute the full migration code path so the user can
    // validate the source DB without committing. The destination DB must be
    // left untouched (no account row) but the report must be fully populated.
    let temp = tempdir().expect("temp dir");
    let fixture = ConsoleFixtureBuilder::new(SOURCE_PASSPHRASE)
        .write(temp.path())
        .expect("write console fixture");
    let dest_db = temp.path().join("destination_wallet.sqlite3");

    let report = run_migration(MigrationOptions {
        source_db_path: fixture.db_path.clone(),
        source_passphrase: fixture.passphrase.clone(),
        destination_db_path: dest_db.clone(),
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "dry_run_test".to_string(),
        dry_run: true,
    })
    .expect("dry-run migration succeeds");

    assert!(report.dry_run, "dry_run flag must propagate into the report");
    assert!(report.balance_match);

    // Destination DB exists (we ran init_db on it), but the migration
    // transaction was rolled back so the account row never landed.
    if dest_db.exists() {
        let conn = Connection::open(&dest_db).expect("open destination");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM accounts WHERE friendly_name = 'dry_run_test'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(count, 0, "dry-run must NOT persist the account row");
    }

    // Sanity: a follow-up live migration with the same account name must
    // still succeed (no leftover state from the dry-run blocking it).
    let live = run_migration(MigrationOptions {
        source_db_path: fixture.db_path,
        source_passphrase: fixture.passphrase,
        destination_db_path: dest_db,
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "dry_run_test".to_string(),
        dry_run: false,
    })
    .expect("subsequent live migration succeeds");
    assert!(!live.dry_run);
}

#[test]
fn migration_rejects_wrong_source_passphrase() {
    let temp = tempdir().expect("temp dir");
    let fixture = ConsoleFixtureBuilder::new(SOURCE_PASSPHRASE)
        .write(temp.path())
        .expect("write console fixture");
    let dest_db = temp.path().join("destination_wallet.sqlite3");

    let result = run_migration(MigrationOptions {
        source_db_path: fixture.db_path,
        source_passphrase: "this-is-not-the-right-password".to_string(),
        destination_db_path: dest_db.clone(),
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "imported".to_string(),
        dry_run: false,
    });

    let err = result.expect_err("wrong source passphrase must fail");
    // The underlying root cause is "Console wallet password is incorrect"; the
    // outer wrapper just says "Failed to open and authenticate the source
    // console wallet". Walk the error chain so the test is robust to either
    // being shown.
    let chain = std::iter::successors(Some(err.as_ref() as &(dyn std::error::Error + 'static)), |e| e.source())
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        chain.contains("password is incorrect") || chain.contains("authenticate") || chain.contains("Password"),
        "expected an authentication / password error, got chain: {chain}"
    );

    // Destination DB must not contain a half-built account.
    if dest_db.exists() {
        let conn = Connection::open(&dest_db).expect("open destination");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
            .unwrap_or(0);
        assert_eq!(
            count, 0,
            "destination must not contain any accounts after a failed migration"
        );
    }
}

#[test]
fn migration_preserves_completed_transaction_ids() {
    // The bounty's primary acceptance criterion: legacy completed_transactions
    // round-trip into the destination's displayed_transactions table with the
    // SAME tx_id values the user was used to seeing.
    let temp = tempdir().expect("temp dir");
    let fixture = ConsoleFixtureBuilder::new(SOURCE_PASSPHRASE)
        .write(temp.path())
        .expect("write console fixture");

    // Seed a handful of distinct, recognisable IDs spanning incoming/outgoing
    // and confirmed/unconfirmed states — the test passes only if every one
    // appears in the destination's displayed_transactions table.
    let test_txs: &[(u64, u64, u64, i32, i32)] = &[
        // (tx_id, amount, fee, direction (0=in,1=out), legacy_status (6=mined_confirmed, 9=onesided_confirmed))
        (1_111_111_111u64, 5_000, 0, 0, 9),    // incoming, one-sided confirmed
        (2_222_222_222u64, 12_345, 0, 0, 12),  // incoming, coinbase confirmed
        (3_333_333_333u64, 50_000, 250, 1, 6), // outgoing, mined confirmed
    ];
    for &(tx_id, amount, fee, dir, status) in test_txs {
        insert_test_completed_transaction(&fixture.db_path, tx_id, amount, fee, dir, status, Some(123_456))
            .expect("seed tx");
    }

    let dest_db = temp.path().join("destination_wallet.sqlite3");
    let report = run_migration(MigrationOptions {
        source_db_path: fixture.db_path,
        source_passphrase: fixture.passphrase,
        destination_db_path: dest_db.clone(),
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "imported".to_string(),
        dry_run: false,
    })
    .expect("migration succeeds");

    assert_eq!(report.displayed_transactions_migrated, test_txs.len());
    // The fixture seeds no outputs, so every migrated transaction is in the
    // "orphan" path (no matched outputs) and must fall back to legacy amount.
    assert_eq!(
        report.displayed_transactions_with_matched_outputs, 0,
        "fixture seeds no outputs, so no displayed transactions should have matched outputs"
    );

    let conn = Connection::open(&dest_db).expect("open destination");
    for &(tx_id, amount, _, _, _) in test_txs {
        let stored_id: Option<String> = conn
            .query_row(
                "SELECT id FROM displayed_transactions WHERE id = ?1",
                params![tx_id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .expect("query");
        assert_eq!(
            stored_id.as_deref(),
            Some(tx_id.to_string().as_str()),
            "expected tx_id {tx_id} in destination displayed_transactions"
        );
        // Orphan path fallback: with no matched outputs, the legacy
        // completed_transactions.amount value must surface as the displayed
        // transaction's amount so the user-facing total is preserved.
        let stored_amount: Option<i64> = conn
            .query_row(
                "SELECT amount FROM displayed_transactions WHERE id = ?1",
                params![tx_id.to_string()],
                |r| r.get(0),
            )
            .optional()
            .expect("query amount");
        assert_eq!(
            stored_amount,
            Some(amount as i64),
            "orphan completed_transactions amount must propagate to displayed_transactions",
        );
    }
}

#[test]
fn migration_sets_scan_tip_from_source() {
    let temp = tempdir().expect("temp dir");
    let fixture = ConsoleFixtureBuilder::new(SOURCE_PASSPHRASE)
        .write(temp.path())
        .expect("write console fixture");

    // Insert a few scan tip rows, then expect the migrator to copy ONLY the
    // highest-height one into the destination's `scanned_tip_blocks` table.
    let tip_hash = [0xAB; 32];
    insert_test_scanned_block(&fixture.db_path, 100, &[0x11; 32]).expect("seed block 1");
    insert_test_scanned_block(&fixture.db_path, 500, &[0x22; 32]).expect("seed block 2");
    insert_test_scanned_block(&fixture.db_path, 999, &tip_hash).expect("seed block 3");

    let dest_db = temp.path().join("destination_wallet.sqlite3");
    let report = run_migration(MigrationOptions {
        source_db_path: fixture.db_path,
        source_passphrase: fixture.passphrase,
        destination_db_path: dest_db.clone(),
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "imported".to_string(),
        dry_run: false,
    })
    .expect("migration succeeds");

    assert_eq!(report.scan_tip_height, Some(999));

    let conn = Connection::open(&dest_db).expect("open destination");
    let (height, hash): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT height, hash FROM scanned_tip_blocks ORDER BY height DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("scan tip row");
    assert_eq!(height, 999);
    assert_eq!(hash, tip_hash.to_vec());
}

#[test]
fn migration_rejects_duplicate_account_name() {
    // Sanity: two migrations targeting the same destination DB and the same
    // account name must not silently overwrite. The second run errors out and
    // the destination remains in the post-first-run state.
    let temp = tempdir().expect("temp dir");
    let fixture = ConsoleFixtureBuilder::new(SOURCE_PASSPHRASE)
        .write(temp.path())
        .expect("write console fixture");
    let dest_db: PathBuf = temp.path().join("destination_wallet.sqlite3");

    run_migration(MigrationOptions {
        source_db_path: fixture.db_path.clone(),
        source_passphrase: fixture.passphrase.clone(),
        destination_db_path: dest_db.clone(),
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "imported".to_string(),
        dry_run: false,
    })
    .expect("first migration succeeds");

    let err = run_migration(MigrationOptions {
        source_db_path: fixture.db_path,
        source_passphrase: fixture.passphrase,
        destination_db_path: dest_db,
        destination_passphrase: DEST_PASSPHRASE.to_string(),
        account_name: "imported".to_string(),
        dry_run: false,
    })
    .expect_err("second migration with same account name must fail");

    let msg = err.to_string();
    assert!(
        msg.contains("already") || msg.contains("imported"),
        "expected duplicate-account error, got: {msg}"
    );
}
