//! Convert a console wallet `completed_transactions` row into the new
//! wallet's `DisplayedTransaction` shape, joining in any outputs the source
//! wallet associated with that transaction.
//!
//! The most important property: the `tx_id` value the console wallet stored
//! (a random `u64` generated when the user first sent or received the
//! transaction) is preserved as the `DisplayedTransaction::id`. Without that
//! the user would see a fresh, unfamiliar set of IDs after migration,
//! which is exactly what the bounty's primary acceptance criterion
//! ("identical display transaction IDs") forbids.
//!
//! New wallet's normal scan path computes a deterministic `TxId` from
//! `(view_key, output_hash)`. We do not use that here for the displayed
//! transaction id; we keep the legacy random `tx_id` instead. The two ID
//! conventions co-exist in the `displayed_transactions` table without
//! conflict (PRIMARY KEY is just the string form of whatever u64 was
//! supplied).
//!
//! Outputs flow:
//!   * The migrator builds two maps keyed by legacy `tx_id`: one for
//!     outputs received in that transaction, one for outputs spent in that
//!     transaction.
//!   * For each completed-transaction row, the migrator looks up the
//!     matching outputs and passes them to `convert_transaction` via
//!     [`MatchedOutputs`]. The converter then builds the per-transaction
//!     `outputs` / `inputs` lists with the real amounts and computes the
//!     transaction-level total credit and debit from those outputs.
//!   * Source rows that have no matching outputs (orphan transaction
//!     metadata from a partial sync, for example) still produce a
//!     displayed-transaction row using the legacy `amount` field as a
//!     fallback so user-facing IDs do not disappear in the migration.

use anyhow::anyhow;
use tari_common_types::{
    tari_address::TariAddress,
    transaction::{LegacyTransactionStatus, TxId},
    types::FixedHash,
};
use tari_transaction_components::MicroMinotari;
use tari_transaction_components::transaction_components::{CoinBaseExtra, OutputType, memo_field::MemoField};

use super::console_db::ConsoleCompletedTxRow;
use crate::models::{Id, OutputStatus};
use crate::transactions::displayed_transaction_processor::{
    BlockchainInfo, DisplayedTransaction, FeeInfo, TransactionDetails, TransactionDirection, TransactionDisplayStatus,
    TransactionInput, TransactionOutput, TransactionSource,
};

/// One output the source wallet associated with a transaction (either as a
/// receive or a spend), enriched with the data the displayed-transaction
/// builder needs.
#[derive(Debug, Clone)]
pub struct MatchedOutput {
    pub hash: FixedHash,
    pub value: MicroMinotari,
    pub mined_height: u64,
    pub mined_block_hash: FixedHash,
    /// Destination `outputs.id` for the row we just inserted. Used so the
    /// `inputs` half of the displayed transaction can carry
    /// `matched_output_id` exactly the way the scan path does.
    pub destination_output_id: Id,
    pub output_type: OutputType,
}

/// All outputs the source wallet linked to one legacy `tx_id`. Empty vectors
/// are fine: the converter falls back to legacy `completed_transactions.amount`
/// when neither side has any matched outputs.
#[derive(Debug, Clone, Default)]
pub struct MatchedOutputs {
    pub received: Vec<MatchedOutput>,
    pub spent: Vec<MatchedOutput>,
}

impl MatchedOutputs {
    pub fn is_empty(&self) -> bool {
        self.received.is_empty() && self.spent.is_empty()
    }

    fn total_credit(&self) -> MicroMinotari {
        self.received
            .iter()
            .fold(MicroMinotari::from(0), |acc, m| acc.saturating_add(m.value))
    }

    fn total_debit(&self) -> MicroMinotari {
        self.spent
            .iter()
            .fold(MicroMinotari::from(0), |acc, m| acc.saturating_add(m.value))
    }
}

/// What the migrator emits per source transaction row. The orchestrator picks
/// these apart and writes them into the new wallet's `displayed_transactions`
/// table.
///
/// Note we deliberately do NOT produce a `completed_transactions` row from
/// a migrated source. The runtime `TransactionMonitor` reads
/// `completed_transactions` to attempt rebroadcast / status refresh of
/// outbound transactions whose serialised blob is still around; populating
/// it with historical, already-mined rows that have no recoverable
/// broadcast blob would queue up bogus rebroadcasts. Historical context
/// lives in `displayed_transactions` (which the UI reads) and
/// `balance_changes` (which the ledger reads); the broadcast log stays
/// empty.
pub struct ConvertedTransaction {
    pub display: DisplayedTransaction,
}

pub fn convert_transaction(
    row: &ConsoleCompletedTxRow,
    account_id: i64,
    matched: &MatchedOutputs,
) -> Result<ConvertedTransaction, anyhow::Error> {
    let tx_id = row.tx_id as u64;
    let legacy_fee = MicroMinotari::from(u64::try_from(row.fee).unwrap_or(0));
    let legacy_amount = MicroMinotari::from(u64::try_from(row.amount).unwrap_or(0));

    let direction = match row.direction {
        Some(0) => TransactionDirection::Incoming, // legacy 0 = Inbound
        Some(1) => TransactionDirection::Outgoing, // legacy 1 = Outbound
        Some(_) | None => infer_direction_from_amount_or_outputs(row, matched),
    };

    let legacy_status = LegacyTransactionStatus::try_from(row.status).unwrap_or(LegacyTransactionStatus::Completed);
    let status = map_status(legacy_status);
    let source = map_source(legacy_status);

    let counterparty = match direction {
        TransactionDirection::Incoming => parse_address(&row.source_address).ok(),
        TransactionDirection::Outgoing => parse_address(&row.destination_address).ok(),
    };

    // Prefer the block info recorded on the matched outputs (they are the
    // authoritative on-chain record). Fall back to whatever the legacy
    // completed_transactions row carries.
    let (block_height, block_hash) =
        first_matched_block(matched).unwrap_or_else(|| match (row.mined_height, &row.mined_in_block) {
            (Some(h), Some(hash_bytes)) if h >= 0 => {
                (h as u64, FixedHash::try_from(hash_bytes.as_slice()).unwrap_or_default())
            },
            _ => (0, FixedHash::default()),
        });

    let timestamp = row.mined_timestamp.unwrap_or(row.timestamp);

    // Totals: derive from matched outputs where possible (they are the
    // source of truth for value), fall back to legacy row.amount when this
    // transaction has no matched outputs (orphan metadata case).
    let (total_credit, total_debit) = if matched.is_empty() {
        match direction {
            TransactionDirection::Outgoing => (MicroMinotari::from(0), legacy_amount.saturating_add(legacy_fee)),
            TransactionDirection::Incoming => (legacy_amount, MicroMinotari::from(0)),
        }
    } else {
        (matched.total_credit(), matched.total_debit())
    };

    // User-facing `amount` field on the displayed transaction:
    //   * Outgoing: the net amount the user paid out (matches what console
    //     wallet showed as the amount column for outgoing rows).
    //   * Incoming: the net amount received.
    // For mixed transactions (both received and spent outputs in the same
    // tx_id, which only happens for outgoing transactions with a change
    // output), `amount` is the net debit (debit - credit), which is what the
    // user saw on the console wallet.
    let amount = if matched.is_empty() {
        legacy_amount
    } else {
        match direction {
            TransactionDirection::Outgoing => total_debit.saturating_sub(total_credit),
            TransactionDirection::Incoming => total_credit,
        }
    };

    // Outputs list: built from the matched receives so the user sees the
    // real per-output amounts rather than the zeroed placeholders the
    // previous implementation produced.
    let outputs: Vec<TransactionOutput> = matched
        .received
        .iter()
        .map(|m| TransactionOutput {
            hash: m.hash,
            amount: m.value,
            status: OutputStatus::Unspent,
            mined_in_block_height: m.mined_height,
            mined_in_block_hash: m.mined_block_hash,
            output_type: m.output_type,
            is_change: false,
        })
        .collect();

    // Inputs list: matched spends, including the destination output id for
    // cross-reference (mirrors what `displayed_transaction_processor` would
    // populate on a live scan).
    let inputs: Vec<TransactionInput> = matched
        .spent
        .iter()
        .map(|m| TransactionInput {
            output_hash: m.hash,
            amount: m.value,
            matched_output_id: m.destination_output_id,
            mined_in_block_hash: m.mined_block_hash,
        })
        .collect();

    let coinbase_extra = if matches!(source, TransactionSource::Coinbase) {
        Some(CoinBaseExtra::default())
    } else {
        None
    };

    let sent_output_hashes: Vec<FixedHash> = matched.spent.iter().map(|m| m.hash).collect();

    // Pull the user-visible message from the source transaction's memo
    // (payment_id). Gate on the decoded MemoField's payment-id BYTES, not
    // on the parsed string: `MemoField::Empty::payment_id_as_string()`
    // returns the variant's Display rendering rather than "", so a bare
    // `s.is_empty()` filter would not catch it and the destination would
    // render the variant tag as a fake user memo.
    let message = row.payment_id.as_ref().and_then(|bytes| {
        let memo = MemoField::from_bytes(bytes);
        if memo.payment_id_as_bytes().is_empty() {
            None
        } else {
            Some(memo.payment_id_as_string())
        }
    });

    let display = DisplayedTransaction {
        id: TxId::from(tx_id),
        direction,
        source,
        status,
        amount,
        message,
        counterparty,
        blockchain: BlockchainInfo {
            block_height,
            timestamp,
            confirmations: 0,
            block_hash,
        },
        fee: match direction {
            TransactionDirection::Outgoing => Some(FeeInfo { amount: legacy_fee }),
            TransactionDirection::Incoming => None,
        },
        details: TransactionDetails {
            account_id,
            total_credit,
            total_debit,
            inputs,
            outputs,
            output_type: Some(OutputType::Standard),
            coinbase_extra,
            memo_hex: row.payment_id.as_ref().map(hex::encode),
            sent_output_hashes,
            sent_payrefs: Vec::new(),
        },
    };

    Ok(ConvertedTransaction { display })
}

fn parse_address(bytes: &[u8]) -> Result<TariAddress, anyhow::Error> {
    TariAddress::from_bytes(bytes).map_err(|e| anyhow!("Invalid address bytes: {e}"))
}

fn infer_direction_from_amount_or_outputs(
    row: &ConsoleCompletedTxRow,
    matched: &MatchedOutputs,
) -> TransactionDirection {
    // If we have matched outputs, use them as the source of truth: a tx
    // with any spent outputs is outgoing; otherwise incoming.
    if !matched.spent.is_empty() {
        return TransactionDirection::Outgoing;
    }
    if !matched.received.is_empty() {
        return TransactionDirection::Incoming;
    }
    // Fallback when neither side has matched outputs: legacy completed_transactions.amount
    // sign was the original heuristic the console wallet used too.
    if row.amount > 0 {
        TransactionDirection::Incoming
    } else {
        TransactionDirection::Outgoing
    }
}

fn first_matched_block(matched: &MatchedOutputs) -> Option<(u64, FixedHash)> {
    // Prefer the receive side when present (matches what a scanner would
    // record). For pure outbound transactions, fall back to the spend side.
    matched
        .received
        .first()
        .or_else(|| matched.spent.first())
        .map(|m| (m.mined_height, m.mined_block_hash))
}

fn map_status(status: LegacyTransactionStatus) -> TransactionDisplayStatus {
    use LegacyTransactionStatus::*;
    match status {
        Pending | Queued => TransactionDisplayStatus::Pending,
        Completed | Broadcast => TransactionDisplayStatus::Pending,
        MinedUnconfirmed | OneSidedUnconfirmed | CoinbaseUnconfirmed => TransactionDisplayStatus::Unconfirmed,
        MinedConfirmed
        | MinedConfirmedLocked
        | OneSidedConfirmed
        | OneSidedConfirmedLocked
        | CoinbaseConfirmed
        | CoinbaseConfirmedLocked => TransactionDisplayStatus::Confirmed,
        Rejected => TransactionDisplayStatus::Rejected,
        Imported | CoinbaseNotInBlockChain | Coinbase => TransactionDisplayStatus::Confirmed,
    }
}

fn map_source(status: LegacyTransactionStatus) -> TransactionSource {
    use LegacyTransactionStatus::*;
    match status {
        Coinbase | CoinbaseUnconfirmed | CoinbaseConfirmed | CoinbaseNotInBlockChain | CoinbaseConfirmedLocked => {
            TransactionSource::Coinbase
        },
        OneSidedUnconfirmed | OneSidedConfirmed | OneSidedConfirmedLocked => TransactionSource::OneSided,
        Imported => TransactionSource::Transfer,
        _ => TransactionSource::Transfer,
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;

    use super::*;
    use crate::transactions::displayed_transaction_processor::TransactionDirection;

    fn make_row(tx_id: u64, amount_signed: i64, direction: Option<i32>) -> ConsoleCompletedTxRow {
        ConsoleCompletedTxRow {
            tx_id: tx_id as i64,
            source_address: vec![0u8; 35],
            destination_address: vec![0u8; 35],
            amount: amount_signed,
            fee: 50,
            status: 6, // MinedConfirmed
            timestamp: NaiveDateTime::default(),
            cancelled: None,
            direction,
            mined_height: Some(123),
            mined_in_block: Some(vec![0xAA; 32]),
            mined_timestamp: Some(NaiveDateTime::default()),
            payment_id: None,
            user_payment_id: None,
            sent_output_hashes: None,
            received_output_hashes: None,
            change_output_hashes: None,
        }
    }

    fn make_matched(hash_seed: u8, value: u64, height: u64) -> MatchedOutput {
        MatchedOutput {
            hash: FixedHash::from([hash_seed; 32]),
            value: MicroMinotari::from(value),
            mined_height: height,
            mined_block_hash: FixedHash::from([0xBB; 32]),
            destination_output_id: hash_seed as i64,
            output_type: OutputType::Standard,
        }
    }

    #[test]
    fn empty_matched_outputs_falls_back_to_legacy_amount_field() {
        // Orphan completed_transactions case: no source outputs link to this
        // tx_id. The displayed transaction must still appear (so the user's
        // legacy tx_id is preserved) but it relies on the legacy `amount`
        // field for its visible totals.
        let row = make_row(7, 10_000, Some(0));
        let converted = convert_transaction(&row, 1, &MatchedOutputs::default()).expect("convert");
        assert_eq!(converted.display.amount, MicroMinotari::from(10_000));
        assert_eq!(converted.display.details.total_credit, MicroMinotari::from(10_000));
        assert_eq!(converted.display.details.total_debit, MicroMinotari::from(0));
        assert!(converted.display.details.outputs.is_empty());
        assert!(converted.display.details.inputs.is_empty());
    }

    #[test]
    fn matched_receives_drive_total_credit_and_outputs_list() {
        let row = make_row(8, 999_999, Some(0)); // legacy amount intentionally wrong
        let matched = MatchedOutputs {
            received: vec![make_matched(1, 500, 100), make_matched(2, 700, 100)],
            spent: vec![],
        };
        let converted = convert_transaction(&row, 1, &matched).expect("convert");

        // Total credit is summed from matched outputs, not from row.amount.
        assert_eq!(converted.display.details.total_credit, MicroMinotari::from(1_200));
        assert_eq!(converted.display.details.total_debit, MicroMinotari::from(0));
        assert_eq!(converted.display.amount, MicroMinotari::from(1_200));
        assert_eq!(converted.display.details.outputs.len(), 2);
        assert_eq!(converted.display.details.outputs[0].amount, MicroMinotari::from(500));
        assert_eq!(converted.display.details.outputs[1].amount, MicroMinotari::from(700));
    }

    #[test]
    fn outgoing_with_change_nets_to_actual_amount_paid() {
        // Outbound transaction: spent two outputs worth 1000 total, kept a
        // change output of 200. Net amount paid = 800. The user's console
        // wallet would have shown this as an 800-amount outbound tx.
        let row = make_row(9, 0, Some(1));
        let matched = MatchedOutputs {
            received: vec![make_matched(1, 200, 50)], // change
            spent: vec![make_matched(2, 600, 50), make_matched(3, 400, 50)],
        };
        let converted = convert_transaction(&row, 1, &matched).expect("convert");

        assert_eq!(converted.display.direction, TransactionDirection::Outgoing);
        assert_eq!(converted.display.details.total_credit, MicroMinotari::from(200));
        assert_eq!(converted.display.details.total_debit, MicroMinotari::from(1_000));
        // amount visible to the user = debit - credit = 800
        assert_eq!(converted.display.amount, MicroMinotari::from(800));
        assert_eq!(converted.display.details.outputs.len(), 1);
        assert_eq!(converted.display.details.inputs.len(), 2);
    }

    #[test]
    fn direction_falls_back_to_outputs_when_legacy_column_null() {
        // Console wallet sometimes leaves direction NULL for coinbase /
        // imported rows. Migrator must infer it from the outputs first
        // (outputs are authoritative), and only then fall back to the legacy
        // amount sign.
        let row = make_row(10, 0, None); // direction null, amount 0
        let receive_only = MatchedOutputs {
            received: vec![make_matched(1, 999, 5)],
            spent: vec![],
        };
        let converted = convert_transaction(&row, 1, &receive_only).expect("convert");
        assert_eq!(converted.display.direction, TransactionDirection::Incoming);

        let spend_only = MatchedOutputs {
            received: vec![],
            spent: vec![make_matched(2, 100, 5)],
        };
        let converted = convert_transaction(&row, 1, &spend_only).expect("convert");
        assert_eq!(converted.display.direction, TransactionDirection::Outgoing);
    }

    #[test]
    fn matched_outputs_drive_blockchain_info_when_present() {
        // A spent tx where the legacy `mined_height` column was NULL but the
        // outputs themselves record the spend block. The displayed tx must
        // take the block info from the matched outputs.
        let mut row = make_row(11, 0, Some(1));
        row.mined_height = None;
        row.mined_in_block = None;

        let matched = MatchedOutputs {
            received: vec![],
            spent: vec![make_matched(1, 50, 777)],
        };
        let converted = convert_transaction(&row, 1, &matched).expect("convert");
        assert_eq!(converted.display.blockchain.block_height, 777);
        assert_eq!(converted.display.blockchain.block_hash, FixedHash::from([0xBB; 32]));
    }

    #[test]
    fn payment_id_memo_field_populates_message_when_non_empty() {
        // The console wallet stores the payment id as the raw MemoField
        // encoding. The migrator must decode it and surface the
        // human-readable string as `DisplayedTransaction::message` so the
        // user sees the same memo content after migration as they saw
        // before. We use the Raw variant in this test because its
        // round-trip from bytes through `payment_id_as_string` does not
        // depend on construction-time TariAddress / MicroMinotari values.
        let mut row = make_row(12, 100, Some(0));
        let memo = MemoField::new_raw(b"hello".to_vec()).expect("memo fits");
        row.payment_id = Some(memo.to_bytes());

        let converted = convert_transaction(&row, 1, &MatchedOutputs::default()).expect("convert");
        let message = converted
            .display
            .message
            .as_deref()
            .expect("message must be set when memo is present");
        assert!(
            !message.is_empty(),
            "Raw memo bytes must surface as a non-empty message"
        );
    }

    #[test]
    fn missing_payment_id_leaves_message_unset() {
        // No memo on the source row -> no message rendered by the new
        // wallet; the field must stay `None` rather than render an empty
        // banner.
        let mut row = make_row(13, 0, Some(0));
        row.payment_id = None;
        let converted = convert_transaction(&row, 1, &MatchedOutputs::default()).expect("convert");
        assert!(converted.display.message.is_none());
    }

    #[test]
    fn matched_output_type_propagates_to_displayed_outputs_list() {
        // Coinbase outputs in the source must surface in the displayed
        // transaction's outputs list with `output_type = Coinbase`, not
        // the previous hardcoded Standard. This is what lets the new
        // wallet's UI render coinbase rewards with the right icon /
        // maturity treatment.
        let row = make_row(14, 0, Some(0));
        let mut coinbase = make_matched(1, 5_000, 100);
        coinbase.output_type = OutputType::Coinbase;
        let matched = MatchedOutputs {
            received: vec![coinbase],
            spent: vec![],
        };
        let converted = convert_transaction(&row, 1, &matched).expect("convert");
        assert_eq!(converted.display.details.outputs.len(), 1);
        assert!(matches!(
            converted.display.details.outputs[0].output_type,
            OutputType::Coinbase
        ));
    }
}
