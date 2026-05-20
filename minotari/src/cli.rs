use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tari_common::configuration::Network;
use tari_transaction_components::tari_amount::MicroMinotari;

/// Command-line interface definition for the Tari wallet.
///
/// This struct is the root of the CLI argument parser, containing all available
/// subcommands for wallet operations. It uses the `clap` crate for argument parsing.
///
/// # Subcommands
///
/// - [`Commands::CreateAddress`] - Generate a new wallet address
/// - [`Commands::ImportViewKey`] - Import an existing wallet by view key
/// - [`Commands::Scan`] - Scan blockchain for transactions
/// - [`Commands::ReScan`] - Re-scan from a specific block height
/// - [`Commands::Daemon`] - Run continuous scanning daemon
/// - [`Commands::Balance`] - Display wallet balance
/// - [`Commands::CreateUnsignedTransaction`] - Build an unsigned transaction
/// - [`Commands::LockFunds`] - Lock UTXOs for a pending transaction
#[derive(Parser)]
#[command(name = "tari", about = "Tari wallet CLI", version, long_about = None)]
pub struct Cli {
    /// Path to the configuration file
    #[arg(long, default_value = "config/config.toml")]
    pub config: PathBuf,

    /// The network to connect to.
    /// If omitted, the value from config.toml is used.
    #[arg(long, help = "TARI Network (mainnet, esmeralda, stagenet, nextnet, localnet, igor)")]
    pub network: Option<Network>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Debug)]
pub struct SecurityArgs {
    /// Password to encrypt/decrypt the wallet file.
    #[arg(short, long, help = "Wallet password")]
    pub password: String,
}

#[derive(Args, Debug)]
pub struct DatabaseArgs {
    /// Path to the SQLite database file storing wallet state.
    #[arg(short = 'd', long, help = "Path to the SQLite database")]
    pub database_path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct NodeArgs {
    /// Base URL of the Tari HTTP RPC API endpoint.
    #[arg(short = 'u', long, help = "The base URL of the Tari HTTP API")]
    pub base_url: Option<String>,

    /// Number of blocks to fetch per API request for efficiency.
    #[arg(long, help = "Batch size for scanning")]
    pub batch_size: Option<u64>,
}

#[derive(Args, Debug)]
pub struct AccountArgs {
    /// Specific account to operate on.
    #[arg(short, long, help = "The name of the target account")]
    pub account_name: Option<String>,
}

#[derive(Args, Debug)]
pub struct TransactionArgs {
    /// Unique key to prevent duplicate transactions.
    #[arg(long, help = "Optional idempotency key")]
    pub idempotency_key: Option<String>,

    /// The number of blocks to consider an output confirmed.
    #[arg(long, help = "Confirmation window")]
    pub confirmation_window: Option<u64>,
}

/// Available CLI subcommands for wallet operations.
///
/// Each variant represents a distinct operation that can be performed on the wallet.
/// Commands are organized by their primary function: wallet management, blockchain
/// scanning, balance queries, and transaction operations.
///
/// # Wallet Management Commands
///
/// - [`Commands::CreateAddress`] - Generate a brand new wallet
/// - [`Commands::ImportViewKey`] - Import an existing wallet using keys
///
/// # Scanning Commands
///
/// - [`Commands::Scan`] - One-time blockchain scan
/// - [`Commands::ReScan`] - Re-scan from a specific height (useful for recovery)
/// - [`Commands::Daemon`] - Continuous scanning with REST API
///
/// # Query Commands
///
/// - [`Commands::Balance`] - View current wallet balance
///
/// # Transaction Commands
///
/// - [`Commands::CreateUnsignedTransaction`] - Create a transaction for offline signing
/// - [`Commands::LockFunds`] - Reserve UTXOs for pending operations
#[derive(Subcommand)]
pub enum Commands {
    /// Create a new wallet address with optional encryption.
    ///
    /// Generates a new wallet with:
    /// - Random cipher seed
    /// - Mnemonic seed words (English)
    /// - View key (private) and spend key (public)
    /// - Tari address for receiving funds
    ///
    /// The output file can be encrypted with a password using XChaCha20-Poly1305.
    /// If no password is provided, keys are stored in plaintext (not recommended
    /// for production use).
    ///
    /// # Output Format
    ///
    /// The generated JSON file contains:
    /// - `address`: Base58-encoded Tari address
    /// - `view_key` / `encrypted_view_key`: Private view key
    /// - `spend_key` / `encrypted_spend_key`: Public spend key
    /// - `seed_words` / `encrypted_seed_words`: Mnemonic recovery phrase
    /// - `birthday`: Block height when wallet was created
    /// - `nonce`: (encrypted only) Encryption nonce
    CreateAddress {
        #[arg(short, long, help = "Password to encrypt the wallet file")]
        password: Option<String>,

        /// Path to write the wallet credentials JSON file.
        #[arg(short, long, help = "Path to the output file", default_value = "data/output.json")]
        output_file: PathBuf,
    },

    /// Scan the blockchain for incoming transactions.
    ///
    /// Performs a partial scan of the blockchain starting from the last scanned
    /// height, looking for outputs that belong to the wallet. Detected outputs
    /// are recorded in the database and can be viewed with the `balance` command.
    ///
    /// # Scanning Process
    ///
    /// 1. Fetches blocks from the Tari HTTP API
    /// 2. Decrypts output commitments using the view key
    /// 3. Records detected outputs in the SQLite database
    /// 4. Updates the scanned tip height
    ///
    /// # Performance Tuning
    ///
    /// - `max_blocks_to_scan`: Limits scan duration (default: 50)
    /// - `batch_size`: Number of blocks per API request (default: 100)
    Scan {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        account: AccountArgs,

        /// Maximum number of blocks to scan in this invocation.
        #[arg(short = 'n', long, default_value_t = 50)]
        max_blocks_to_scan: u64,
    },

    /// Re-scan the blockchain from a specific height.
    ///
    /// Rolls back the wallet state to a specified block height and re-scans
    /// from that point. This is useful for:
    ///
    /// - Recovering from database corruption
    /// - Handling blockchain reorganizations
    /// - Debugging missing transactions
    ///
    /// # Warning
    ///
    /// This operation modifies the database by removing outputs detected
    /// after the specified height. Make a backup before re-scanning.
    ReScan {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        db: DatabaseArgs,

        /// Name of the account to re-scan (Required).
        #[arg(short, long, help = "Account name to re-scan")]
        account_name: String,

        /// Block height to roll back to before re-scanning.
        #[arg(short = 'r', long, help = "Re-scan from height")]
        rescan_from_height: u64,
    },

    /// Run the wallet daemon for continuous blockchain monitoring.
    ///
    /// Starts a long-running process that:
    /// - Continuously scans the blockchain at regular intervals
    /// - Exposes a REST API for wallet operations
    /// - Automatically unlocks expired UTXO locks
    /// - Handles graceful shutdown on Ctrl+C
    ///
    /// # API Endpoints
    ///
    /// The daemon exposes endpoints for:
    /// - Balance queries: `GET /accounts/{name}/balance`
    /// - Fund locking: `POST /accounts/{name}/lock_funds`
    /// - Transaction creation: `POST /accounts/{name}/create_unsigned_transaction`
    ///
    /// API documentation is available at `/swagger-ui/` when the daemon is running.
    ///
    /// # Shutdown
    ///
    /// Press Ctrl+C to initiate graceful shutdown. The daemon will:
    /// 1. Stop accepting new API requests
    /// 2. Complete the current scan cycle
    /// 3. Close database connections
    Daemon {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        db: DatabaseArgs,

        /// Seconds to wait between scan cycles.
        #[arg(short, long, help = "Interval between scans in seconds")]
        scan_interval_secs: Option<u64>,
        /// TCP port for the REST API server.
        #[arg(long, help = "Port for the API server")]
        api_port: Option<u16>,
    },

    /// Display the wallet balance.
    ///
    /// Shows the current balance for one or all accounts in the wallet.
    /// Balance is calculated as the sum of confirmed outputs minus spent inputs.
    ///
    /// # Output Format
    ///
    /// Displays balance in both microTari (base units) and Tari with proper
    /// formatting and thousand separators for readability.
    Balance {
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        account: AccountArgs,
    },

    /// Import a wallet using view and spend keys.
    ///
    /// Creates a new account in the database using existing cryptographic keys.
    /// This is useful for:
    ///
    /// - Restoring a wallet from backed-up keys
    /// - Creating a watch-only wallet (view key only)
    /// - Importing a wallet generated by another application
    ///
    /// # Key Format
    ///
    /// Both keys should be provided as hex-encoded strings:
    /// - `view_private_key`: 64 hex characters (32 bytes)
    /// - `spend_public_key`: 64 hex characters (32 bytes, compressed)
    ///
    /// # Birthday
    ///
    /// The birthday is the block height when the wallet was created. Setting
    /// this correctly avoids scanning unnecessary historical blocks.
    ImportViewKey {
        /// Private view key in hexadecimal format.
        #[arg(short, long, alias = "view_key", help = "The view key in hex format")]
        view_private_key: String,
        /// Public spend key in hexadecimal format (compressed point).
        #[arg(short, long, alias = "spend_key", help = "The spend public key in hex format")]
        spend_public_key: String,

        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,

        /// Block height when the wallet was created (for scan optimization).
        #[arg(short, long, help = "The wallet birthday (block height)", default_value = "0")]
        birthday: u16,
    },

    /// Create a new wallet or restore from seed words.
    ///
    /// This initializes the database with a full signing wallet (SeedWordsWallet).
    /// - If `seed_words` are provided, it restores the wallet.
    /// - If omitted, it generates a generic random wallet.
    Create {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        account: AccountArgs,

        /// Optional space-separated seed words to restore from.
        #[arg(short, long, help = "Restore from specific seed words (space separated)")]
        seed_words: Option<String>,
    },

    /// Reveal the seed words for a specific wallet.
    ///
    /// Requires the wallet password to decrypt the seed.
    /// Will fail if the wallet is a View-Only wallet or Ledger wallet.
    ShowSeedWords {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        account: AccountArgs,
    },

    /// Reveal the cryptographic keys for a specific wallet.
    ///
    /// Outputs the Private View Key (used for scanning) and the Public Spend Key
    /// (used to generate addresses). Requires the wallet password.
    ShowKeys {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        account: AccountArgs,
    },

    /// Create an unsigned one-sided transaction.
    ///
    /// Builds a transaction that can be signed offline. The transaction sends
    /// funds to one or more recipients using one-sided (non-interactive) payments.
    ///
    /// # Recipient Format
    ///
    /// Recipients are specified as `address::amount` or `address::amount::payment_id`:
    /// - `address`: Base58-encoded Tari address
    /// - `amount`: Amount in microTari
    /// - `payment_id`: Optional memo/reference (max 48 characters)
    ///
    /// # UTXO Locking
    ///
    /// Input UTXOs are automatically locked to prevent double-spending. If the
    /// transaction is not broadcast within `seconds_to_lock`, the UTXOs are
    /// automatically released.
    ///
    /// # Example
    ///
    /// ```bash
    /// tari create-unsigned-transaction \
    ///     --account-name main \
    ///     --recipient "f2ABC...123::1000000" \
    ///     --password secret
    /// ```
    CreateUnsignedTransaction {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        tx: TransactionArgs,

        /// Name of the account to spend from.
        #[arg(short, long, help = "Name of the account to send from")]
        account_name: String,
        /// Recipients in `address::amount[::payment_id]` format. Repeatable.
        #[arg(
            short,
            long,
            help = "Recipient address, amount and optional payment id (e.g., address::amount or address::amount::payment_id). Can be specified multiple times."
        )]
        recipient: Vec<String>,
        /// Path to write the unsigned transaction JSON.
        #[arg(
            short,
            long,
            help = "Path to the output file for the unsigned transaction",
            default_value = "data/unsigned_transaction.json"
        )]
        output_file: String,
        /// Duration in seconds to lock input UTXOs (default: 24 hours).
        #[arg(long, help = "Optional seconds to lock UTXOs", default_value_t = 86400)]
        seconds_to_lock: u64,
    },

    /// Lock funds (reserve UTXOs) for a pending transaction.
    ///
    /// Reserves a set of UTXOs totaling at least the specified amount plus
    /// estimated fees. Locked UTXOs cannot be used for other transactions
    /// until they are either spent or the lock expires.
    ///
    /// # Use Case
    ///
    /// This is useful when you need to:
    /// - Reserve funds before creating a complex multi-step transaction
    /// - Ensure sufficient funds are available for a future payment
    /// - Coordinate multiple transactions without double-spending
    ///
    /// # Automatic Unlock
    ///
    /// If the locked funds are not spent within `seconds_to_lock_utxos`,
    /// they are automatically unlocked and become available again.
    LockFunds {
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        tx: TransactionArgs,

        /// Name of the account to lock funds from.
        #[arg(short, long, help = "Name of the account to send from")]
        account_name: String,
        /// Path to write the locked funds details JSON.
        #[arg(
            short,
            long,
            help = "Path to the output file for the unsigned transaction",
            default_value = "data/locked_funds.json"
        )]
        output_file: String,
        /// Amount to lock in microTari.
        #[arg(short = 'm', long, help = "Amount to lock")]
        amount: MicroMinotari,
        /// Number of output UTXOs to create (for splitting).
        #[arg(short, long, help = "Optional number of outputs", default_value = "1")]
        num_outputs: usize,
        /// Fee rate in microTari per gram of transaction weight.
        #[arg(short, long, help = "Optional fee per gram", default_value = "5")]
        fee_per_gram: MicroMinotari,
        /// Estimated size of outputs for fee calculation.
        #[arg(short, long, help = "Optional estimated output size")]
        estimated_output_size: Option<usize>,
        /// Duration in seconds before locked UTXOs are released (default: 24h).
        #[arg(
            short,
            long,
            help = "Optional seconds to lock (will be unlocked if not spent)",
            default_value = "86400"
        )]
        seconds_to_lock_utxos: Option<u64>,
    },
    /// Register a validator node on the Tari base layer.
    ///
    /// Creates, signs, and broadcasts a pay-to-self transaction that embeds the validator
    /// node's public key and pre-computed signature into the output features, locking the
    /// consensus-required minimum deposit back to the wallet.
    ///
    /// # Prerequisites
    ///
    /// - The account must be a full SeedWords wallet (view-only wallets are not supported)
    /// - The caller must pre-compute the validator node signature using the VN's private key
    ///   via `ValidatorNodeSignature::sign_for_registration` on the validator node side
    ///
    /// # Signature Format
    ///
    /// The signature is a Schnorr signature split into two 32-byte hex-encoded components:
    /// - `--vn-sig-nonce`: the public nonce (compressed Ristretto point)
    /// - `--vn-sig`: the signature scalar
    RegisterValidatorNode {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        tx: TransactionArgs,

        /// Name of the account to fund the registration deposit from.
        #[arg(short, long, help = "Name of the account to fund the deposit from")]
        account_name: String,

        /// Validator node public key (hex-encoded, 32 bytes).
        #[arg(long, help = "Validator node public key (hex)")]
        vn_public_key: String,

        /// Public nonce component of the validator node signature (hex-encoded, 32 bytes).
        #[arg(long, help = "Validator node signature public nonce (hex)")]
        vn_sig_nonce: String,

        /// Scalar component of the validator node signature (hex-encoded, 32 bytes).
        #[arg(long, help = "Validator node signature scalar (hex)")]
        vn_sig: String,

        /// Claim public key for validator node rewards (hex-encoded, 32 bytes).
        #[arg(long, help = "Claim public key for VN rewards (hex)")]
        claim_public_key: String,

        /// Maximum epoch for replay protection.
        #[arg(long, help = "Max epoch for replay protection")]
        max_epoch: u64,

        /// Fee rate in MicroMinotari per gram (default: 5).
        #[arg(long, default_value_t = 5)]
        fee_per_gram: u64,

        /// Optional payment ID or memo attached to the transaction.
        #[arg(long, help = "Optional payment ID or memo")]
        payment_id: Option<String>,

        /// Optional sidechain deployment key (hex-encoded private key, 32 bytes).
        /// If provided, proves ownership of the sidechain and is included in the signature.
        #[arg(long, help = "Optional sidechain deployment private key (hex)")]
        sidechain_deployment_key: Option<String>,

        /// Duration in seconds to lock input UTXOs (default: 24 hours).
        #[arg(long, help = "Seconds to lock UTXOs", default_value_t = 86400)]
        seconds_to_lock: u64,
    },

    /// Submit a validator node exit transaction on the Tari base layer.
    ///
    /// Creates, signs, and broadcasts a pay-to-self transaction that signals the validator
    /// node's intention to leave the active set. The transaction embeds the validator node's
    /// public key and pre-computed exit signature into the output features.
    ///
    /// # Prerequisites
    ///
    /// - The account must be a full SeedWords wallet (view-only wallets are not supported)
    /// - The caller must pre-compute the validator node signature using the VN's private key
    ///   via `ValidatorNodeSignature::sign_for_exit` on the validator node side
    ///
    /// # Signature Format
    ///
    /// The signature is a Schnorr signature split into two 32-byte hex-encoded components:
    /// - `--vn-sig-nonce`: the public nonce (compressed Ristretto point)
    /// - `--vn-sig`: the signature scalar
    ///
    /// The exit signature does NOT include a claim public key (unlike registration).
    SubmitValidatorNodeExit {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        tx: TransactionArgs,

        /// Name of the account to fund the exit deposit from.
        #[arg(short, long, help = "Name of the account to fund the deposit from")]
        account_name: String,

        /// Validator node public key (hex-encoded, 32 bytes).
        #[arg(long, help = "Validator node public key (hex)")]
        vn_public_key: String,

        /// Public nonce component of the validator node signature (hex-encoded, 32 bytes).
        #[arg(long, help = "Validator node signature public nonce (hex)")]
        vn_sig_nonce: String,

        /// Scalar component of the validator node signature (hex-encoded, 32 bytes).
        #[arg(long, help = "Validator node signature scalar (hex)")]
        vn_sig: String,

        /// Maximum epoch for replay protection.
        #[arg(long, help = "Max epoch for replay protection")]
        max_epoch: u64,

        /// Fee rate in MicroMinotari per gram (default: 5).
        #[arg(long, default_value_t = 5)]
        fee_per_gram: u64,

        /// Optional payment ID or memo attached to the transaction.
        #[arg(long, help = "Optional payment ID or memo")]
        payment_id: Option<String>,

        /// Optional sidechain deployment key (hex-encoded private key, 32 bytes).
        /// If provided, proves ownership of the sidechain and is included in the signature.
        #[arg(long, help = "Optional sidechain deployment private key (hex)")]
        sidechain_deployment_key: Option<String>,

        /// Duration in seconds to lock input UTXOs (default: 24 hours).
        #[arg(long, help = "Seconds to lock UTXOs", default_value_t = 86400)]
        seconds_to_lock: u64,
    },

    /// Submit a validator node eviction proof transaction on the Tari base layer.
    ///
    /// Creates, signs, and broadcasts a pay-to-self transaction that embeds a self-validating
    /// eviction proof into the output features. The proof contains sidechain quorum certificates
    /// and a Merkle inclusion proof — no additional wallet signature is required.
    ///
    /// # Prerequisites
    ///
    /// - The account must be a full SeedWords wallet (view-only wallets are not supported)
    /// - The eviction proof must be provided as a JSON file (e.g., generated by the sidechain node)
    ///
    /// # Proof File Format
    ///
    /// The proof file must contain a JSON-serialized [`EvictionProof`] as produced by the
    /// sidechain node. The proof is self-validating via embedded quorum certificates.
    SubmitValidatorEvictionProof {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        node: NodeArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        tx: TransactionArgs,

        /// Name of the account to fund the eviction deposit from.
        #[arg(short, long, help = "Name of the account to fund the deposit from")]
        account_name: String,

        /// Path to a JSON file containing the serialized EvictionProof.
        #[arg(long, help = "Path to the eviction proof JSON file")]
        proof_file: std::path::PathBuf,

        /// Fee rate in MicroMinotari per gram (default: 5).
        #[arg(long, default_value_t = 5)]
        fee_per_gram: u64,

        /// Optional payment ID or memo attached to the transaction.
        #[arg(long, help = "Optional payment ID or memo")]
        payment_id: Option<String>,

        /// Optional sidechain deployment key (hex-encoded private key, 32 bytes).
        /// If provided, creates a knowledge proof signed over the evicted node's public key.
        #[arg(long, help = "Optional sidechain deployment private key (hex)")]
        sidechain_deployment_key: Option<String>,

        /// Duration in seconds to lock input UTXOs (default: 24 hours).
        #[arg(long, help = "Seconds to lock UTXOs", default_value_t = 86400)]
        seconds_to_lock: u64,
    },

    /// Delete a wallet account and all associated data.
    ///
    /// This permanently removes the account, transaction history, and keys from the database.
    Delete {
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        account: AccountArgs,
    },

    /// Burn funds and generate an L2 claim proof.
    ///
    /// Creates a burn transaction that destroys L1 funds. After the transaction is
    /// confirmed on-chain, the daemon automatically fetches the kernel merkle proof
    /// from the base node and writes a complete `CompleteClaimBurnProof` JSON file
    /// to the configured `burn_proofs_dir` directory.
    ///
    /// # Claim Public Key
    ///
    /// The `--claim-public-key` is the L2 wallet's public key. The L2 wallet can use
    /// this key to decrypt the encrypted output value and verify the ownership proof.
    ///
    /// # Example
    ///
    /// ```bash
    /// tari burn-funds \
    ///     --account-name main \
    ///     --amount 1000000 \
    ///     --claim-public-key <hex> \
    ///     --password secret
    /// ```
    BurnFunds {
        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,
        #[command(flatten)]
        tx: TransactionArgs,
        #[command(flatten)]
        burn: BurnArgs,
        #[command(flatten)]
        node: NodeArgs,

        /// Name of the account to burn funds from.
        #[arg(short, long, help = "Name of the account to burn from")]
        account_name: String,
        /// Amount to burn in microTari.
        #[arg(short = 'm', long, help = "Amount to burn in microTari")]
        amount: MicroMinotari,
        /// L2 claim public key (hex). Required to generate an L2 claim proof.
        #[arg(long, help = "L2 claim public key in hex")]
        claim_public_key: Option<String>,
        /// Sidechain deployment key (hex), for L2 template burns.
        #[arg(long, help = "Sidechain deployment key in hex")]
        sidechain_deployment_key: Option<String>,
        /// Fee rate in microTari per gram.
        #[arg(short, long, help = "Fee per gram", default_value_t = MicroMinotari(5))]
        fee_per_gram: MicroMinotari,
        /// Optional payment memo.
        #[arg(long, help = "Optional payment memo")]
        payment_id: Option<String>,
        /// Seconds to lock UTXOs while the transaction confirms.
        #[arg(long, default_value_t = 86400)]
        seconds_to_lock: u64,
    },

    /// Migrate an already-synced legacy console wallet database into this
    /// wallet's database format.
    ///
    /// Reads the legacy console wallet's SQLite file (read-only), recovers the
    /// master cipher seed using the provided source passphrase, and copies the
    /// outputs and transaction history into a new account in the destination
    /// database. The migrated account preserves the legacy random transaction
    /// IDs as the user-facing display IDs, the same balance, and the same set
    /// of unspent outputs - and sets the scan tip to the source's last
    /// scanned block so the next scan does not re-process the entire chain.
    ///
    /// # Example
    ///
    /// ```bash
    /// tari migrate-from-console-wallet \
    ///     --source-db /path/to/console_wallet/console_wallet.sqlite3 \
    ///     --source-password "old wallet password" \
    ///     --account-name imported \
    ///     --password "new wallet password"
    /// ```
    MigrateFromConsoleWallet {
        /// Path to the legacy console wallet's SQLite database.
        #[arg(long, help = "Path to the source console wallet SQLite database")]
        source_db: PathBuf,

        /// Passphrase that unlocks the source console wallet.
        #[arg(long, help = "Source console wallet passphrase")]
        source_password: String,

        #[command(flatten)]
        security: SecurityArgs,
        #[command(flatten)]
        db: DatabaseArgs,

        /// Friendly name to give the new account in this wallet.
        #[arg(short = 'a', long, help = "Account name for the migrated wallet")]
        account_name: String,

        /// Run the migration against an in-flight transaction but roll it
        /// back instead of committing. Useful for checking the source DB
        /// would migrate cleanly (balance match, no schema conflicts, no
        /// tx_id collisions that need fallback ids) before touching the
        /// destination wallet.
        #[arg(long, help = "Validate the migration without writing the destination DB")]
        dry_run: bool,
    },
}

#[derive(Args, Debug)]
pub struct BurnArgs {
    /// Directory where burn proof JSON files are written by the daemon.
    /// Defaults to `<platform data dir>/tari/<network>/burn_proofs`.
    #[arg(long, help = "Directory for burn proof output files (daemon only)")]
    pub burn_proofs_dir: Option<PathBuf>,
}

pub struct DaemonArgs {
    pub scan_interval_secs: Option<u64>,
    pub api_port: Option<u16>,
}

pub trait ApplyArgs {
    fn apply_database(&mut self, args: &DatabaseArgs);
    fn apply_node(&mut self, args: &NodeArgs);
    fn apply_account(&mut self, args: &AccountArgs);
    fn apply_transaction(&mut self, args: &TransactionArgs);
    fn apply_burn(&mut self, args: &BurnArgs);
    fn apply_daemon(&mut self, args: &DaemonArgs);
}
