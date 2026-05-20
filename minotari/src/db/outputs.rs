use crate::db::balance_changes::{
    get_balance_change_id_by_output, insert_balance_change, mark_balance_change_as_reversed,
};
use crate::db::error::{WalletDbError, WalletDbResult};
use crate::log::mask_amount;
use crate::models::BalanceChange;
use crate::models::OutputStatus;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use rusqlite::{Connection, named_params};
use serde::Deserialize;
use serde_rusqlite::from_rows;
use tari_common_types::payment_reference::PaymentReference;
use tari_common_types::transaction::TxId;
use tari_common_types::types::FixedHash;
use tari_common_types::types::PrivateKey;
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::WalletOutput;
use tari_transaction_components::utxo_selection::UtxoValue;
use tari_utilities::ByteArray;

#[allow(clippy::too_many_arguments)]
pub fn insert_output(
    conn: &Connection,
    account_id: i64,
    account_view_key: &PrivateKey,
    output_hash: Vec<u8>,
    output: &WalletOutput,
    block_height: u64,
    block_hash: &FixedHash,
    mined_timestamp: u64,
    memo_parsed: Option<String>,
    memo_hex: Option<String>,
    payment_reference: PaymentReference,
    is_burn: bool,
) -> WalletDbResult<i64> {
    info!(
        target: "audit",
        account_id = account_id,
        value = &*mask_amount(output.value()),
        height = block_height;
        "DB: Inserting output"
    );

    let tx_id = TxId::new_deterministic(account_view_key.as_bytes(), &output.output_hash()).as_i64_wrapped();

    let output_json = serde_json::to_string(&output)?;

    #[allow(clippy::cast_possible_wrap)]
    let mined_timestamp_dt = DateTime::<Utc>::from_timestamp(mined_timestamp as i64, 0)
        .ok_or_else(|| WalletDbError::Decoding(format!("Invalid mined timestamp: {}", mined_timestamp)))?;

    #[allow(clippy::cast_possible_wrap)]
    let block_height = block_height as i64;
    #[allow(clippy::cast_possible_wrap)]
    let value = output.value().as_u64() as i64;
    #[allow(clippy::cast_possible_wrap)]
    let maturity = output.features().maturity as i64;
    let payment_reference_hex = hex::encode(payment_reference.as_slice());

    conn.execute(
        r#"
       INSERT INTO outputs (
            account_id,
            tx_id,
            output_hash,
            mined_in_block_height,
            mined_in_block_hash,
            value,
            mined_timestamp,
            wallet_output_json,
            memo_parsed,
            memo_hex,
            payment_reference,
            is_burn,
            maturity
       )
       VALUES (
            :account_id,
            :tx_id,
            :output_hash,
            :block_height,
            :block_hash,
            :value,
            :mined_timestamp,
            :output_json,
            :memo_parsed,
            :memo_hex,
            :payment_reference,
            :is_burn,
            :maturity
       )
        "#,
        named_params! {
            ":account_id": account_id,
            ":tx_id": tx_id,
            ":output_hash": output_hash,
            ":block_height": block_height,
            ":block_hash": block_hash.as_slice(),
            ":value": value,
            ":mined_timestamp": mined_timestamp_dt,
            ":output_json": output_json,
            ":memo_parsed": memo_parsed,
            ":memo_hex": memo_hex,
            ":payment_reference": payment_reference_hex,
            ":is_burn": is_burn,
            ":maturity": maturity,
        },
    )?;

    Ok(conn.last_insert_rowid())
}

pub fn get_output_info_by_hash(
    conn: &Connection,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<(i64, TxId, WalletOutput)>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, tx_id, wallet_output_json
        FROM outputs
        WHERE output_hash = :output_hash AND deleted_at IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! { ":output_hash": output_hash.as_slice() })?;
    let row: Option<WalletOutputRow> = from_rows(rows).next().transpose()?;
    let data = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let output: WalletOutput = serde_json::from_str(&data.wallet_output_json)?;

    let tx_id = TxId::from(data.tx_id as u64);

    Ok(Some((data.id, tx_id, output)))
}

pub fn get_output_info_by_hash_for_account(
    conn: &Connection,
    account_id: i64,
    output_hash: &FixedHash,
) -> WalletDbResult<Option<(i64, TxId, WalletOutput)>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, tx_id, wallet_output_json
        FROM outputs
        WHERE account_id = :account_id AND output_hash = :output_hash AND deleted_at IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":output_hash": output_hash.as_slice(),
    })?;
    let row: Option<WalletOutputRow> = from_rows(rows).next().transpose()?;
    let data = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let output: WalletOutput = serde_json::from_str(&data.wallet_output_json)?;

    let tx_id = TxId::from(data.tx_id as u64);

    Ok(Some((data.id, tx_id, output)))
}

#[derive(Deserialize)]
pub struct UnconfirmedOutputRow {
    pub output_hash: FixedHash,
    pub mined_in_block_height: i64,
    pub memo_parsed: Option<String>,
    pub memo_hex: Option<String>,
    pub tx_id: i64,
    pub is_burn: i64,
}

pub fn get_unconfirmed_outputs(
    conn: &Connection,
    account_id: i64,
    current_height: u64,
    confirmation_blocks: u64,
) -> WalletDbResult<Vec<UnconfirmedOutputRow>> {
    let min_height_to_confirm = current_height.saturating_sub(confirmation_blocks);
    #[allow(clippy::cast_possible_wrap)]
    let min_height = min_height_to_confirm as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT output_hash, mined_in_block_height, memo_parsed, memo_hex, tx_id, is_burn
        FROM outputs o
        WHERE o.account_id = :account_id
          AND o.mined_in_block_height <= :min_height
          AND o.confirmed_height IS NULL
          AND o.deleted_at IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":min_height": min_height
    })?;

    let result_rows: Vec<UnconfirmedOutputRow> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;
    Ok(result_rows)
}

pub fn mark_output_confirmed(
    conn: &Connection,
    output_hash: &FixedHash,
    confirmed_height: u64,
    confirmed_hash: &[u8],
) -> WalletDbResult<()> {
    info!(
        target: "audit",
        height = confirmed_height;
        "DB: Output Confirmed"
    );

    #[allow(clippy::cast_possible_wrap)]
    let confirmed_height = confirmed_height as i64;
    conn.execute(
        r#"
        UPDATE outputs
        SET confirmed_height = :height, confirmed_hash = :hash
        WHERE output_hash = :output_hash
        "#,
        named_params! {
            ":height": confirmed_height,
            ":hash": confirmed_hash,
            ":output_hash": output_hash.to_vec(),
        },
    )?;

    Ok(())
}

#[derive(Deserialize)]
struct OutputToDelete {
    id: i64,
    value: i64,
}

pub fn soft_delete_outputs_from_height(conn: &Connection, account_id: i64, height: u64) -> WalletDbResult<()> {
    warn!(
        target: "audit",
        account_id = account_id,
        height = height;
        "DB: Soft deleting outputs (Reorg)"
    );
    #[allow(clippy::cast_possible_wrap)]
    let height_i64 = height as i64;
    let now = Utc::now();

    let outputs_to_delete = {
        let mut stmt = conn.prepare_cached(
            r#"
            SELECT id, value
            FROM outputs
            WHERE account_id = :account_id AND mined_in_block_height >= :height AND deleted_at IS NULL
            "#,
        )?;

        let rows = stmt.query(named_params! {
            ":account_id": account_id,
            ":height": height_i64
        })?;

        from_rows::<OutputToDelete>(rows).collect::<Result<Vec<_>, _>>()?
    };

    for output_row in outputs_to_delete {
        // Find and mark the original balance change as reversed
        let original_balance_change_id = get_balance_change_id_by_output(conn, output_row.id)?;
        if let Some(original_id) = original_balance_change_id {
            mark_balance_change_as_reversed(conn, original_id)?;
        }

        let balance_change = BalanceChange {
            account_id,
            caused_by_output_id: Some(output_row.id),
            caused_by_input_id: None,
            description: format!("Reversal: Output found in blockchain scan (reorg at height {})", height),
            balance_credit: 0.into(),
            balance_debit: (output_row.value as u64).into(),
            effective_date: now.naive_utc(),
            effective_height: height,
            claimed_recipient_address: None,
            claimed_sender_address: None,
            memo_parsed: None,
            memo_hex: None,
            claimed_fee: None,
            claimed_amount: None,
            is_reversal: true,
            reversal_of_balance_change_id: original_balance_change_id,
            is_reversed: false,
        };
        insert_balance_change(conn, &balance_change)?;
    }

    conn.execute(
        r#"
        UPDATE outputs
        SET deleted_at = :now, deleted_in_block_height = :height, payment_reference = NULL
        WHERE account_id = :account_id AND mined_in_block_height >= :height AND deleted_at IS NULL
        "#,
        named_params! {
            ":now": now,
            ":height": height_i64,
            ":account_id": account_id
        },
    )?;

    Ok(())
}

pub fn update_output_status(conn: &Connection, output_id: i64, status: OutputStatus) -> WalletDbResult<()> {
    debug!(
        output_id = output_id,
        status:% = status;
        "DB: Updating output status"
    );

    let status_str = status.to_string();
    conn.execute(
        r#"
        UPDATE outputs
        SET status = :status
        WHERE id = :id
        "#,
        named_params! {
            ":status": status_str,
            ":id": output_id
        },
    )?;

    Ok(())
}

pub fn lock_output(
    conn: &Connection,
    output_id: i64,
    locked_by_request_id: &str,
    locked_at: DateTime<Utc>,
) -> WalletDbResult<()> {
    info!(
        target: "audit",
        output_id = output_id,
        request_id = locked_by_request_id;
        "DB: Locking output"
    );

    let locked_status = OutputStatus::Locked.to_string();
    let unspent_status = OutputStatus::Unspent.to_string();

    conn.execute(
        r#"
        UPDATE outputs
        SET status = :locked_status, locked_by_request_id = :req_id, locked_at = :locked_at
        WHERE id = :id and status = :unspent_status
        "#,
        named_params! {
            ":locked_status": locked_status,
            ":req_id": locked_by_request_id,
            ":locked_at": locked_at,
            ":id": output_id,
            ":unspent_status": unspent_status,
        },
    )?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbWalletOutput {
    pub id: i64,
    pub tx_id: TxId,
    pub output: WalletOutput,
}

impl UtxoValue for DbWalletOutput {
    fn value(&self) -> MicroMinotari {
        self.output.value()
    }
}

#[derive(Deserialize, Debug)]
struct WalletOutputRow {
    id: i64,
    tx_id: i64,
    wallet_output_json: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbOutput {
    pub id: i64,
    pub account_id: i64,
    pub output_hash: Vec<u8>,
    pub mined_in_block_hash: Vec<u8>,
    pub mined_in_block_height: i64,
    pub value: i64,
    pub created_at: chrono::NaiveDateTime,
    pub wallet_output_json: Option<String>,
    pub mined_timestamp: chrono::NaiveDateTime,
    pub confirmed_height: Option<i64>,
    pub confirmed_hash: Option<Vec<u8>>,
    pub memo_parsed: Option<String>,
    pub memo_hex: Option<String>,
    pub status: String,
    pub locked_at: Option<chrono::NaiveDateTime>,
    pub locked_by_request_id: Option<String>,
    pub deleted_at: Option<chrono::NaiveDateTime>,
    pub deleted_in_block_height: Option<i64>,
    pub payment_reference: Option<String>,
    pub maturity: i64,
}

impl DbOutput {
    pub fn to_wallet_output(&self) -> WalletDbResult<WalletOutput> {
        let output_str = self
            .wallet_output_json
            .as_ref()
            .ok_or_else(|| WalletDbError::Unexpected("Output JSON is null".to_string()))?;
        let output: WalletOutput = serde_json::from_str(output_str)?;
        Ok(output)
    }
}

pub fn get_output_by_id(conn: &Connection, output_id: i64) -> WalletDbResult<Option<DbOutput>> {
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, account_id, output_hash, mined_in_block_hash, mined_in_block_height,
               value, created_at, wallet_output_json, mined_timestamp, confirmed_height,
               confirmed_hash, memo_parsed, memo_hex, status, locked_at, locked_by_request_id,
               deleted_at, deleted_in_block_height, payment_reference, maturity
        FROM outputs
        WHERE id = :id
        "#,
    )?;

    let rows = stmt.query(named_params! { ":id": output_id })?;
    let output: Option<DbOutput> = from_rows(rows).next().transpose()?;
    Ok(output)
}

pub fn fetch_unspent_outputs(
    conn: &Connection,
    account_id: i64,
    min_height: u64,
    tip_height: u64,
) -> WalletDbResult<Vec<DbWalletOutput>> {
    let unspent_status = OutputStatus::Unspent.to_string();
    #[allow(clippy::cast_possible_wrap)]
    let min_height_i64 = min_height as i64;
    // Clamp to i64::MAX so very-large `tip_height` values do not wrap to a
    // negative i64 (which would invert the maturity comparison).
    #[allow(clippy::cast_possible_wrap)]
    let tip_height_i64 = tip_height.min(i64::MAX as u64) as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT id, tx_id, wallet_output_json
        FROM outputs
        WHERE account_id = :account_id
          AND status = :unspent_status
          AND mined_in_block_height <= :min_height
          AND maturity >= 0
          AND maturity <= :tip_height
          AND deleted_at IS NULL
          AND is_burn = 0
        ORDER BY value DESC
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":unspent_status": unspent_status,
        ":min_height": min_height_i64,
        ":tip_height": tip_height_i64,
    })?;
    let raw_rows: Vec<WalletOutputRow> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;

    let mut outputs = Vec::new();
    for row in raw_rows {
        let output: WalletOutput = serde_json::from_str(&row.wallet_output_json)?;
        outputs.push(DbWalletOutput {
            id: row.id,
            tx_id: TxId::from(row.tx_id as u64),
            output,
        });
    }
    Ok(outputs)
}

pub fn unlock_outputs_for_request(conn: &Connection, locked_by_request_id: &str) -> WalletDbResult<()> {
    debug!(
        request_id = locked_by_request_id;
        "DB: Unlocking outputs for request"
    );

    let unspent_status = OutputStatus::Unspent.to_string();
    let locked_status = OutputStatus::Locked.to_string();

    conn.execute(
        r#"
        UPDATE outputs
        SET status = :unspent, locked_at = NULL, locked_by_request_id = NULL
        WHERE locked_by_request_id = :req_id AND status = :locked
        "#,
        named_params! {
            ":unspent": unspent_status,
            ":req_id": locked_by_request_id,
            ":locked": locked_status
        },
    )?;

    Ok(())
}

pub fn fetch_outputs_by_lock_request_id(
    conn: &Connection,
    locked_by_request_id: &str,
) -> WalletDbResult<Vec<DbWalletOutput>> {
    let mut stmt =
        conn.prepare_cached("SELECT id, tx_id, wallet_output_json FROM outputs WHERE locked_by_request_id = :req_id")?;

    let rows = stmt.query(named_params! { ":req_id": locked_by_request_id })?;
    let raw_rows: Vec<WalletOutputRow> = from_rows(rows).collect::<Result<Vec<_>, _>>()?;

    let mut outputs = Vec::new();
    for row in raw_rows {
        let output: WalletOutput = serde_json::from_str(&row.wallet_output_json)?;
        outputs.push(DbWalletOutput {
            id: row.id,
            tx_id: TxId::from(row.tx_id as u64),
            output,
        });
    }
    Ok(outputs)
}

#[derive(Deserialize)]
struct OutputTotalsRow {
    locked_val: i64,
    unconfirmed_val: i64,
    immature_val: i64,
    available_val: i64,
}

/// Disjoint UTXO total breakdown for an account, in MicroMinotari.
///
/// Every non-spent, non-burn, non-deleted output is counted in exactly one of
/// `locked`, `unconfirmed`, `immature` or `available`. Precedence (matching the
/// SQL CASE order):
/// 1. `status = LOCKED`                                              → `locked`
/// 2. else `confirmed_height IS NULL`                                → `unconfirmed`
/// 3. else `maturity > tip_height` (or wrapped negative)             → `immature`
/// 4. else                                                           → `available`
///
/// `unavailable = locked + unconfirmed + immature` (the funds the user has but
/// cannot spend right now).
#[derive(Debug, Clone, Copy)]
pub struct OutputTotals {
    pub available: MicroMinotari,
    pub unconfirmed: MicroMinotari,
    pub locked: MicroMinotari,
    pub immature: MicroMinotari,
    pub unavailable: MicroMinotari,
}

/// Retrieves UTXO total breakdowns for an account. `tip_height` is the latest
/// scanned chain tip; an output is `immature` when its maturity is in the
/// future (or wrapped negative due to the u64→i64 cast on insert).
pub fn get_output_totals_for_account(
    conn: &Connection,
    account_id: i64,
    tip_height: u64,
) -> WalletDbResult<OutputTotals> {
    let locked_status = OutputStatus::Locked.to_string();
    let unspent_status = OutputStatus::Unspent.to_string();
    // See `fetch_unspent_outputs` for the rationale behind clamping.
    #[allow(clippy::cast_possible_wrap)]
    let tip_height_i64 = tip_height.min(i64::MAX as u64) as i64;

    // Each non-spent, non-burn, non-deleted output falls into exactly one
    // bucket via the precedence baked into the nested CASE expressions.
    let mut stmt = conn.prepare_cached(
        r#"
        SELECT
            COALESCE(SUM(CASE
                WHEN status = :locked THEN value
                ELSE 0
            END), 0) as locked_val,
            COALESCE(SUM(CASE
                WHEN status = :locked THEN 0
                WHEN confirmed_height IS NULL THEN value
                ELSE 0
            END), 0) as unconfirmed_val,
            COALESCE(SUM(CASE
                WHEN status = :locked THEN 0
                WHEN confirmed_height IS NULL THEN 0
                WHEN maturity < 0 OR maturity > :tip_height THEN value
                ELSE 0
            END), 0) as immature_val,
            COALESCE(SUM(CASE
                WHEN status = :unspent
                     AND confirmed_height IS NOT NULL
                     AND maturity >= 0
                     AND maturity <= :tip_height
                THEN value
                ELSE 0
            END), 0) as available_val
        FROM outputs
        WHERE account_id = :account_id AND deleted_at IS NULL AND is_burn = 0
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":locked": locked_status,
        ":unspent": unspent_status,
        ":account_id": account_id,
        ":tip_height": tip_height_i64,
    })?;

    let result = from_rows::<OutputTotalsRow>(rows)
        .next()
        .ok_or_else(|| WalletDbError::Unexpected("Aggregate query returned no rows".to_string()))??;

    let locked: MicroMinotari = (result.locked_val as u64).into();
    let unconfirmed: MicroMinotari = (result.unconfirmed_val as u64).into();
    let immature: MicroMinotari = (result.immature_val as u64).into();
    let available: MicroMinotari = (result.available_val as u64).into();
    let unavailable = locked.saturating_add(unconfirmed).saturating_add(immature);

    Ok(OutputTotals {
        available,
        unconfirmed,
        locked,
        immature,
        unavailable,
    })
}

#[derive(Deserialize)]
pub struct ReorgOutputInfo {
    pub output_hash: Vec<u8>,
    pub mined_in_block_height: i64,
    pub locked_by_request_id: Option<String>,
}

pub fn get_active_outputs_from_height(
    conn: &Connection,
    account_id: i64,
    height: u64,
) -> WalletDbResult<Vec<ReorgOutputInfo>> {
    #[allow(clippy::cast_possible_wrap)]
    let height_i64 = height as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT output_hash, mined_in_block_height, locked_by_request_id
        FROM outputs
        WHERE account_id = :account_id 
          AND mined_in_block_height >= :height 
          AND deleted_at IS NULL
        "#,
    )?;

    let rows = stmt.query(named_params! {
        ":account_id": account_id,
        ":height": height_i64
    })?;

    let results = from_rows::<ReorgOutputInfo>(rows).collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

/// Sum of unspent, mature outputs for an account, in MicroMinotari.
///
/// Outputs whose maturity exceeds `tip_height` are excluded so the caller
/// cannot mistake immature funds for spendable balance.
pub fn get_total_unspent_balance(conn: &Connection, account_id: i64, tip_height: u64) -> WalletDbResult<u64> {
    let unspent_status = OutputStatus::Unspent.to_string();
    // See `fetch_unspent_outputs` for the rationale behind clamping.
    #[allow(clippy::cast_possible_wrap)]
    let tip_height_i64 = tip_height.min(i64::MAX as u64) as i64;

    let mut stmt = conn.prepare_cached(
        r#"
        SELECT COALESCE(SUM(value), 0)
        FROM outputs
        WHERE account_id = :account_id
          AND status = :unspent_status
          AND maturity >= 0
          AND maturity <= :tip_height
          AND deleted_at IS NULL
          AND is_burn = 0
        "#,
    )?;

    let total = stmt.query_row(
        named_params! {
            ":account_id": account_id,
            ":unspent_status": unspent_status,
            ":tip_height": tip_height_i64,
        },
        |row| row.get(0),
    )?;

    Ok(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::cast_lossless)]
    #![allow(clippy::cast_possible_wrap)]
    #![allow(clippy::too_many_arguments)]
    use super::*;
    use crate::db::{create_account, get_account_by_name, init_db};
    use tari_common_types::seeds::cipher_seed::CipherSeed;
    use tari_transaction_components::key_manager::wallet_types::{SeedWordsWallet, WalletType};
    use tempfile::tempdir;

    /// Insert a synthetic outputs row directly. Avoids constructing a real
    /// `WalletOutput` (which requires keys and ranges) so we can assert the
    /// SQL filter logic in isolation.
    fn insert_synthetic_output(
        conn: &Connection,
        account_id: i64,
        output_hash: u8,
        value: u64,
        mined_in_block_height: u64,
        confirmed: bool,
        status: OutputStatus,
        maturity: i64,
    ) {
        let confirmed_height: Option<i64> = if confirmed {
            Some(mined_in_block_height as i64)
        } else {
            None
        };
        let confirmed_hash: Option<Vec<u8>> = if confirmed { Some(vec![1u8; 32]) } else { None };
        conn.execute(
            r#"
            INSERT INTO outputs (
                account_id, tx_id, output_hash, mined_in_block_height, mined_in_block_hash, value,
                mined_timestamp, wallet_output_json, status, confirmed_height, confirmed_hash,
                is_burn, maturity
            ) VALUES (
                :account_id, :tx_id, :output_hash, :height, :block_hash, :value,
                :mined_ts, :json, :status, :confirmed_height, :confirmed_hash,
                0, :maturity
            )
            "#,
            named_params! {
                ":account_id": account_id,
                ":tx_id": output_hash as i64,
                ":output_hash": vec![output_hash; 32],
                ":height": mined_in_block_height as i64,
                ":block_hash": vec![output_hash; 32],
                ":value": value as i64,
                ":mined_ts": Utc::now(),
                ":json": "{}",
                ":status": status.to_string(),
                ":confirmed_height": confirmed_height,
                ":confirmed_hash": confirmed_hash,
                ":maturity": maturity,
            },
        )
        .expect("insert synthetic output");
    }

    fn create_test_account(conn: &Connection) -> i64 {
        let seeds = CipherSeed::random();
        let wallet = WalletType::SeedWords(SeedWordsWallet::construct_new(seeds).unwrap());
        create_account(conn, "default", &wallet, "password").unwrap();
        get_account_by_name(conn, "default").unwrap().unwrap().id
    }

    #[test]
    fn unspent_balance_excludes_immature() {
        // Verifies the maturity filter on the spendable-balance aggregate.
        // (`fetch_unspent_outputs` deserializes `wallet_output_json`, which we
        // can't forge cheaply; the totals query uses the same SQL filter so
        // exercising it here is sufficient.)
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("maturity.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // Mature spendable output (maturity 50 ≤ tip 150).
        insert_synthetic_output(&conn, account_id, 1, 1_000, 100, true, OutputStatus::Unspent, 50);
        // Immature output (maturity 200 > tip 150).
        insert_synthetic_output(&conn, account_id, 2, 5_000, 100, true, OutputStatus::Unspent, 200);
        // Output that matures exactly at the tip — must still be selectable.
        insert_synthetic_output(&conn, account_id, 3, 2_000, 100, true, OutputStatus::Unspent, 150);

        let total = get_total_unspent_balance(&conn, account_id, 150).expect("total");
        assert_eq!(total, 1_000 + 2_000, "immature 5_000 µT must be excluded");

        // Advance the tip past the immature maturity height; it now becomes spendable.
        let total_after_tip = get_total_unspent_balance(&conn, account_id, 200).expect("total");
        assert_eq!(total_after_tip, 1_000 + 5_000 + 2_000);
    }

    #[test]
    fn output_totals_partition_is_disjoint() {
        // Verifies that every output falls into exactly one of available /
        // locked / unconfirmed / immature, with precedence locked >
        // unconfirmed > immature > available, and that
        // `unavailable = locked + unconfirmed + immature`.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("maturity_totals.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // Confirmed, mature, unspent — `available` (1_000).
        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 0);
        // Confirmed, immature, unspent — `immature` (4_000).
        insert_synthetic_output(&conn, account_id, 2, 4_000, 50, true, OutputStatus::Unspent, 500);
        // Unconfirmed, mature, unspent — `unconfirmed` (2_000).
        insert_synthetic_output(&conn, account_id, 3, 2_000, 99, false, OutputStatus::Unspent, 0);
        // Locked, mature, confirmed — `locked` (8_000).
        insert_synthetic_output(&conn, account_id, 4, 8_000, 50, true, OutputStatus::Locked, 0);
        // Locked + unconfirmed + immature — only the highest-precedence bucket
        // (locked) gets credit (16_000).
        insert_synthetic_output(&conn, account_id, 5, 16_000, 99, false, OutputStatus::Locked, 500);

        let totals = get_output_totals_for_account(&conn, account_id, 100).expect("totals");
        assert_eq!(totals.available, MicroMinotari::from(1_000));
        assert_eq!(totals.unconfirmed, MicroMinotari::from(2_000));
        assert_eq!(totals.immature, MicroMinotari::from(4_000));
        assert_eq!(totals.locked, MicroMinotari::from(8_000 + 16_000));
        assert_eq!(totals.unavailable, MicroMinotari::from(2_000 + 4_000 + 8_000 + 16_000));
        // Sanity: every non-spent output was credited exactly once.
        assert_eq!(
            totals.available.saturating_add(totals.unavailable),
            MicroMinotari::from(1_000 + 2_000 + 4_000 + 8_000 + 16_000),
        );
    }

    #[test]
    fn negative_maturity_is_treated_as_immature() {
        // `WalletOutput.features().maturity` is u64 but the column is i64; values
        // above i64::MAX wrap to a negative i64 on insert. Such outputs must be
        // treated as immature (never spendable) rather than slipping through the
        // `maturity <= tip` comparison.
        let temp = tempdir().expect("temp dir");
        let pool = init_db(temp.path().join("maturity_wrap.db")).expect("init db");
        let conn = pool.get().expect("conn");
        let account_id = create_test_account(&conn);

        // Spendable output (small positive maturity).
        insert_synthetic_output(&conn, account_id, 1, 1_000, 50, true, OutputStatus::Unspent, 10);
        // Wrapped maturity (originally u64::MAX → -1 after `as i64`).
        insert_synthetic_output(&conn, account_id, 2, 9_000, 50, true, OutputStatus::Unspent, -1);
        // Another wrap representative.
        insert_synthetic_output(&conn, account_id, 3, 5_000, 50, true, OutputStatus::Unspent, i64::MIN);

        let total = get_total_unspent_balance(&conn, account_id, u64::MAX).expect("total");
        assert_eq!(
            total, 1_000,
            "wrapped-negative maturities must be excluded even at tip = u64::MAX"
        );

        let totals = get_output_totals_for_account(&conn, account_id, u64::MAX).expect("totals");
        // Both wrapped rows count as immature (and unavailable). The non-wrapped
        // row has small positive maturity so it is `available`.
        assert_eq!(totals.available, MicroMinotari::from(1_000));
        assert_eq!(totals.immature, MicroMinotari::from(9_000 + 5_000));
        assert_eq!(totals.unavailable, MicroMinotari::from(9_000 + 5_000));
    }
}
