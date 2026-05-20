// Payref History Step Definitions
//
// Exercises the payref history fallback lookup after a real blockchain reorg.
//
// The test flow:
// 1. Mine blocks on NodeA so the wallet receives coinbase outputs
// 2. Scan the wallet to pick up the outputs (which generates payrefs)
// 3. Capture a payref value from the displayed transactions
// 4. Create an isolated NodeB with a longer chain (different block hashes)
// 5. Restart NodeA connected to NodeB so it adopts the longer chain (reorg)
// 6. Re-scan the wallet — the reorg handler saves old payrefs to payref_history
// 7. Start the daemon and verify the old payref still resolves via history fallback
#![allow(clippy::indexing_slicing)]
use cucumber::{given, then, when};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;
use tari_common::configuration::Network::LocalNet;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_transaction_components::key_manager::wallet_types::WalletType;
use tokio::time::sleep;

use super::common::MinotariWorld;
use super::common::test_support;

// =============================
// Helper Functions
// =============================

/// Find an unused port in a given range.
fn find_free_port(start: u16, end: u16) -> u16 {
    for port in start..end {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("No free port found in range {}..{}", start, end);
}

// =============================
// Step Definitions
// =============================

#[given(expr = "I have an isolated base node {word}")]
async fn start_isolated_base_node(world: &mut MinotariWorld, name: String) {
    // Start a base node with NO seed peers — it creates its own independent chain.
    let base_dir = world.current_base_dir.as_ref().expect("Base dir not set").clone();

    let node = test_support::spawn_base_node(
        &base_dir,
        &mut world.assigned_ports,
        &mut world.base_nodes,
        false, // not a seed node
        name.clone(),
        vec![], // no seed peers — isolated chain
    )
    .await;

    world.base_nodes.insert(name, node);
}

#[then("the wallet should have displayed transactions with payrefs")]
async fn wallet_has_displayed_transactions_with_payrefs(world: &mut MinotariWorld) {
    let port = world
        .api_port
        .expect("Daemon must be running before querying displayed transactions");
    let url = format!(
        "http://127.0.0.1:{}/accounts/default/displayed_transactions?limit=100",
        port
    );

    let client = reqwest::Client::new();
    let txs: Vec<serde_json::Value> = client
        .get(&url)
        .send()
        .await
        .expect("Failed to query displayed transactions via API")
        .json()
        .await
        .expect("Failed to parse displayed transactions response");

    let count = txs
        .iter()
        .filter(|tx| {
            tx["details"]["sent_payrefs"]
                .as_array()
                .map(|arr| !arr.is_empty())
                .unwrap_or(false)
        })
        .count();

    assert!(
        count > 0,
        "Expected at least one displayed transaction with a non-empty payref, found {}",
        count
    );

    println!("Found {} displayed transaction(s) with payrefs", count);
}

#[when("I capture a payref from the displayed transactions")]
async fn capture_payref_from_displayed_transactions(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running before capturing payref");
    let url = format!(
        "http://127.0.0.1:{}/accounts/default/displayed_transactions?limit=100",
        port
    );

    let client = reqwest::Client::new();
    let txs: Vec<serde_json::Value> = client
        .get(&url)
        .send()
        .await
        .expect("Failed to query displayed transactions via API")
        .json()
        .await
        .expect("Failed to parse displayed transactions response");

    // Find the first transaction with at least one payref and extract it
    let captured = txs
        .iter()
        .find_map(|tx| {
            tx["details"]["sent_payrefs"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|p| p.as_str())
                .map(String::from)
        })
        .expect("No displayed transaction with payref found — did the scan generate payrefs?");

    println!("Captured payref for later verification: {}", captured);

    world
        .transaction_data
        .insert("captured_payref".to_string(), serde_json::Value::String(captured));
}

#[when(expr = "I mine {int} blocks on {word} with a different wallet")]
async fn mine_blocks_with_different_wallet(world: &mut MinotariWorld, num_blocks: u64, node_name: String) {
    let node = world
        .base_nodes
        .get(&node_name)
        .unwrap_or_else(|| panic!("Node {} not found", node_name));

    // Generate a completely new random wallet address so the coinbase outputs
    // do NOT belong to our test wallet. This means the reorg will invalidate
    // the original wallet's outputs.
    let other_wallet = WalletType::new_random().unwrap();
    let wallet_address = TariAddress::new_dual_address(
        other_wallet.get_public_view_key(),
        other_wallet.get_public_spend_key(),
        LocalNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .unwrap();

    node.mine_blocks(num_blocks, &wallet_address)
        .await
        .expect("Failed to mine blocks on isolated node");

    let height = node.get_tip_height().await.expect("Failed to get tip height");
    println!(
        "Mined {} blocks on {} with a different wallet, height: {}",
        num_blocks, node_name, height
    );
}

#[when(expr = "I restart {word} connected to {word}")]
async fn restart_node_connected_to(world: &mut MinotariWorld, node_to_restart: String, peer_node: String) {
    // Kill the node we want to restart
    {
        let node = world
            .base_nodes
            .get_mut(&node_to_restart)
            .unwrap_or_else(|| panic!("Node {} not found", node_to_restart));
        node.kill();
    }

    // Small delay for cleanup
    sleep(Duration::from_secs(1)).await;

    let base_dir = world.current_base_dir.as_ref().expect("Base dir not set").clone();

    // Restart the node with the peer node as a seed
    let node = test_support::spawn_base_node(
        &base_dir,
        &mut world.assigned_ports,
        &mut world.base_nodes,
        true,
        node_to_restart.clone(),
        vec![peer_node],
    )
    .await;

    world.base_nodes.insert(node_to_restart, node);
}

#[when(expr = "I wait for {word} to sync to height {int}")]
async fn wait_for_node_to_sync(world: &mut MinotariWorld, node_name: String, expected_height: u64) {
    let node = world
        .base_nodes
        .get(&node_name)
        .unwrap_or_else(|| panic!("Node {} not found", node_name));

    node.wait_for_height(expected_height, 120).await.unwrap_or_else(|e| {
        panic!(
            "Node {} failed to reach height {} within timeout: {}",
            node_name, expected_height, e
        )
    });

    let actual_height = node.get_tip_height().await.expect("Failed to get tip height");
    println!("Node {} synced to height {}", node_name, actual_height);
}

#[when("I start the daemon on a free port")]
async fn start_daemon_on_free_port(world: &mut MinotariWorld) {
    let port = find_free_port(9100, 9200);
    let db_path = world.database_path.as_ref().expect("Database path not set");

    let (command, mut args) = world.get_minotari_command();
    args.push("daemon".to_string());
    args.push("--password".to_string());
    args.push(world.test_password.clone());
    args.push("--database-path".to_string());
    args.push(db_path.to_str().unwrap().to_string());
    args.push("--api-port".to_string());
    args.push(port.to_string());

    // Connect to the first base node if available
    if !world.base_nodes.is_empty() {
        let base_node = world.base_nodes.values().next().unwrap();
        let base_url = format!("http://127.0.0.1:{}", base_node.http_port);
        args.push("--base-url".to_string());
        args.push(base_url);
    }

    let child = Command::new(&command)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start daemon process");

    // Give the daemon time to start up
    sleep(Duration::from_secs(3)).await;

    world.daemon_handle = Some(child);
    world.api_port = Some(port);

    println!("Daemon started on port {}", port);
}

#[when("I request the displayed transactions by the captured payref via the API")]
async fn request_displayed_by_captured_payref(world: &mut MinotariWorld) {
    let port = world.api_port.expect("Daemon must be running");
    let captured_payref = world
        .transaction_data
        .get("captured_payref")
        .and_then(|v| v.as_str())
        .expect("No captured payref found — did 'I capture a payref' step run?")
        .to_string();

    let url = format!(
        "http://127.0.0.1:{}/accounts/default/displayed_transactions/by_payref/{}",
        port, captured_payref
    );

    println!("Querying displayed transactions by captured payref: {}", url);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .expect("Failed to query displayed transactions by payref");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() {
        0
    } else {
        i32::from(status.as_u16())
    });
}

#[when(regex = r#"^I request the displayed transactions by payref "([^"]*)" via the API$"#)]
async fn request_displayed_by_payref(world: &mut MinotariWorld, payref: String) {
    let port = world.api_port.expect("Daemon must be running");
    let url = format!(
        "http://127.0.0.1:{}/accounts/default/displayed_transactions/by_payref/{}",
        port, payref
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .expect("Failed to query displayed transactions by payref");

    let status = response.status();
    let body = response.text().await.expect("Failed to read response body");

    world.last_command_output = Some(body);
    world.last_command_exit_code = Some(if status.is_success() {
        0
    } else {
        i32::from(status.as_u16())
    });
}

#[then("the API should return the displayed transaction via history fallback")]
async fn assert_displayed_transaction_returned(world: &mut MinotariWorld) {
    let body = world
        .last_command_output
        .as_ref()
        .expect("No response body from previous API call");

    let exit = world.last_command_exit_code.unwrap_or(-1);
    assert_eq!(
        exit, 0,
        "Expected 2xx success from API, got exit code {}, body: {}",
        exit, body
    );

    let json: serde_json::Value = serde_json::from_str(body).expect("Response body was not valid JSON");
    let arr = json.as_array().expect("Expected a JSON array response");

    assert!(
        !arr.is_empty(),
        "Expected at least one displayed transaction from the history fallback, got an empty array. Body: {}",
        body
    );

    println!("History fallback resolved {} displayed transaction(s)", arr.len());
}

#[then("the API should return an empty list for the displayed transactions")]
async fn assert_empty_displayed_list(world: &mut MinotariWorld) {
    let body = world
        .last_command_output
        .as_ref()
        .expect("No response body from previous API call");

    let exit = world.last_command_exit_code.unwrap_or(-1);
    assert_eq!(
        exit, 0,
        "Expected 2xx success from API, got exit code {}, body: {}",
        exit, body
    );

    let json: serde_json::Value = serde_json::from_str(body).expect("Response body was not valid JSON");
    let arr = json.as_array().expect("Expected a JSON array response");

    assert!(
        arr.is_empty(),
        "Expected empty array for unknown payref, got {} item(s): {}",
        arr.len(),
        body
    );
}
