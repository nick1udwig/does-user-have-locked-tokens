use alloy_primitives::U256;
use alloy_sol_types::{sol, SolEvent};
use hyperware_process_lib::{
    await_message, call_init,
    eth::{
        Address as EthAddress, BlockNumberOrTag, EthSub, EthSubResult, Filter, Log, Provider,
        SubscriptionResult,
    },
    get_state,
    homepage::add_to_homepage,
    http::server::{
        send_response, HttpBindingConfig, HttpServer, HttpServerRequest, IncomingHttpRequest,
    },
    println, set_state, Address, Message,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

const SUBSCRIPTION_ID: u64 = 1;

wit_bindgen::generate!({
    path: "../target/wit",
    world: "process-v1",
    generate_unused_types: true,
    additional_derives: [serde::Deserialize, serde::Serialize],
});

const ICON: &str = include_str!("./icon");

// Base L2 chain ID
const BASE_CHAIN_ID: u64 = 8453;
// TokenRegistry contract address on Base
const TOKEN_REGISTRY_ADDRESS: &str = "0x0000000000e8d224B902632757d5dbc51a451456";
// Starting block for indexing
const START_BLOCK: u64 = 36283831;

// Define the TokenRegistry events using alloy sol! macro
sol! {
    event TokensLocked(address indexed account, uint256 amount, uint256 duration, uint256 balance, uint256 endTime);
    event TokensWithdrawn(address indexed user, uint256 amountWithdrawn, uint256 remainingAmount, uint256 endTime);
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub balance: U256,
    pub end_time: u64,
}

#[derive(Default, Serialize, Deserialize)]
pub struct AppState {
    locked_accounts: HashMap<String, LockInfo>,
    last_indexed_block: u64,
}

impl AppState {
    fn handle_log(&mut self, log: &Log) {
        let Some(topic0) = log.topics().first() else {
            return;
        };

        if *topic0 == TokensLocked::SIGNATURE_HASH {
            if let Ok(decoded) = TokensLocked::decode_log_data(log.data(), true) {
                let address = format!("{:?}", decoded.account).to_lowercase();
                // endTime is a U256 representing Unix timestamp
                let end_time: u64 = decoded.endTime.try_into().unwrap_or(u64::MAX);
                self.locked_accounts.insert(
                    address.clone(),
                    LockInfo {
                        balance: decoded.balance,
                        end_time,
                    },
                );
                println!(
                    "TokensLocked: {} balance: {} end_time: {}",
                    address, decoded.balance, end_time
                );
            }
        } else if *topic0 == TokensWithdrawn::SIGNATURE_HASH {
            if let Ok(decoded) = TokensWithdrawn::decode_log_data(log.data(), true) {
                let address = format!("{:?}", decoded.user).to_lowercase();
                if decoded.remainingAmount.is_zero() {
                    self.locked_accounts.remove(&address);
                    println!("TokensWithdrawn: {} fully withdrawn", address);
                } else {
                    let end_time: u64 = decoded.endTime.try_into().unwrap_or(u64::MAX);
                    self.locked_accounts.insert(
                        address.clone(),
                        LockInfo {
                            balance: decoded.remainingAmount,
                            end_time,
                        },
                    );
                    println!(
                        "TokensWithdrawn: {} remaining: {} end_time: {}",
                        address, decoded.remainingAmount, end_time
                    );
                }
            }
        }

        if let Some(block_number) = log.block_number {
            if block_number > self.last_indexed_block {
                self.last_indexed_block = block_number;
            }
        }
    }

    fn has_locked_tokens(&self, address: &str) -> bool {
        let normalized = address.to_lowercase();
        let Some(info) = self.locked_accounts.get(&normalized) else {
            return false;
        };

        // Must have non-zero balance
        if info.balance.is_zero() {
            return false;
        }

        // Check if lock is still active (end_time in the future)
        // If system time is before epoch (misconfigured clock), return false conservatively
        let Ok(duration) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        else {
            return false;
        };

        info.end_time > duration.as_secs()
    }

    fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec(self) {
            set_state(&bytes);
        }
    }

    fn load() -> Self {
        match get_state() {
            Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            None => Self::default(),
        }
    }
}

fn make_filter(from_block: Option<u64>) -> Filter {
    let contract_address =
        EthAddress::from_str(TOKEN_REGISTRY_ADDRESS).expect("Invalid contract address");

    let mut filter = Filter::new()
        .address(contract_address)
        .events(vec![TokensLocked::SIGNATURE, TokensWithdrawn::SIGNATURE]);

    if let Some(block) = from_block {
        filter = filter.from_block(block).to_block(BlockNumberOrTag::Latest);
    }

    filter
}

fn index_historical_logs(state: &mut AppState, provider: &Provider) {
    let from_block = if state.last_indexed_block > 0 {
        state.last_indexed_block + 1
    } else {
        START_BLOCK
    };

    println!("Indexing logs from block {}...", from_block);

    loop {
        match provider.get_logs(&make_filter(Some(from_block))) {
            Ok(logs) => {
                println!("Found {} historical logs", logs.len());
                for log in logs {
                    state.handle_log(&log);
                }
                break;
            }
            Err(e) => {
                println!("Error fetching logs: {:?}, retrying in 5s...", e);
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }
}

fn handle_http_request(state: &AppState, req: &IncomingHttpRequest) {
    // Get the address from query params
    let query_params = req.query_params();
    let address = query_params.get("address");

    let is_valid = match address {
        Some(addr) => state.has_locked_tokens(addr),
        None => false,
    };

    // Build the TaskOn-compatible response
    let response = serde_json::json!({
        "result": {
            "isValid": is_valid
        }
    });

    let body = serde_json::to_vec(&response).unwrap_or_default();

    // Send response with JSON content type
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    send_response(http::StatusCode::OK, Some(headers), body);
}

call_init!(init);
fn init(our: Address) {
    println!("Locked tokens checker starting on {}", our.node());

    // Add to homepage
    add_to_homepage("Locked Tokens Checker", Some(ICON), Some("/"), None);

    // Set up HTTP server and bind the verification endpoint
    let mut server = HttpServer::new(5);

    // Bind the TaskOn verification endpoint - public, unauthenticated
    let config = HttpBindingConfig::new(false, false, false, None);
    if let Err(e) = server.bind_http_path("/api/task/verification", config) {
        println!("Failed to bind HTTP path: {:?}", e);
    }

    // Load or create state
    let mut state = AppState::load();

    // Create provider for Base L2
    let provider = Provider::new(BASE_CHAIN_ID, 60);

    // Index historical logs
    index_historical_logs(&mut state, &provider);
    state.save();

    println!(
        "Indexed {} addresses with locked tokens, last block: {}",
        state.locked_accounts.len(),
        state.last_indexed_block
    );

    // Subscribe to new events
    provider.subscribe_loop(SUBSCRIPTION_ID, make_filter(None), 0, 0);
    println!("Subscribed to new events");

    // Main message loop
    loop {
        let Ok(message) = await_message() else {
            println!("Error receiving message");
            continue;
        };

        // Only handle requests (not responses)
        let Message::Request { ref body, .. } = message else {
            continue;
        };

        let source_process = message.source().process.to_string();

        // Handle eth subscription messages
        if source_process == "eth:distro:sys" {
            let Ok(eth_result) = serde_json::from_slice::<EthSubResult>(body) else {
                println!("Failed to parse eth subscription result");
                continue;
            };

            match eth_result {
                Ok(EthSub { result, .. }) => {
                    let Ok(sub_result) = serde_json::from_value::<SubscriptionResult>(result)
                    else {
                        println!("Failed to parse subscription result");
                        continue;
                    };

                    if let SubscriptionResult::Log(log) = sub_result {
                        state.handle_log(&log);
                        state.save();
                        println!(
                            "Processed new log, {} addresses with locked tokens",
                            state.locked_accounts.len()
                        );
                    }
                }
                Err(e) => {
                    println!("Subscription error: {:?}, resubscribing...", e);
                    let _ = provider.unsubscribe(SUBSCRIPTION_ID);
                    provider.subscribe_loop(SUBSCRIPTION_ID, make_filter(None), 0, 0);
                }
            }
            continue;
        }

        // Handle HTTP requests
        if source_process == "http-server:distro:sys" {
            let Ok(http_request) = serde_json::from_slice::<HttpServerRequest>(body) else {
                println!("Failed to parse HTTP request");
                continue;
            };

            match http_request {
                HttpServerRequest::Http(req) => {
                    handle_http_request(&state, &req);
                }
                _ => {
                    // Ignore WebSocket messages
                }
            }
        }
    }
}
