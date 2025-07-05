use shredstream::shredstream_proxy_client::ShredstreamProxyClient;
use shredstream::SubscribeEntriesRequest;
use solana_entry::entry::Entry;
use solana_sdk::signer::Signer;
use solana_sdk::system_instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair};
use solana_sdk::transaction::VersionedTransaction;

use anyhow::{Result};
use serde_json::{json, Value};

use solana_instruction::{AccountMeta, Instruction};
use solana_transaction::Transaction;

use std::str::FromStr;
use tracing::{info};
use tracing_subscriber::EnvFilter;
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

use reqwest::{Client, Proxy};

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};

static SANDWICHES_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn time() -> u128 {
    let now = SystemTime::now();
    let millis = now
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();    
    millis
}

pub fn init_tracing() {
    // This sets up logging with RUST_LOG environment variable
    // If RUST_LOG is not set, defaults to "info" level
    // Use RUST_LOG=off to disable logging entirely
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();
}

pub mod shared {
    tonic::include_proto!("shared");
}

pub mod shredstream {
    tonic::include_proto!("shredstream");
}

fn load_keypair_from_base58(env_var: &str) -> Keypair {
    let bs58_string = std::env::var(env_var).expect("PRIVATE_KEY not set");
    let bytes = bs58::decode(bs58_string)
        .into_vec()
        .expect("Invalid base58 key");

    Keypair::try_from(bytes.as_slice()).expect("Invalid keypair bytes")
}

fn get_random_tip_account() -> Result<String> {
    let tip_accounts = vec![
        "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5",
        "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
        "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY",
        "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49",
        "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh",
        "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt",
        "DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL",
        "3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT",
    ];

    let random_index = rand::rng().random_range(0..tip_accounts.len());
    Ok(tip_accounts[random_index].to_string())
}

fn get_program_ids() -> Vec<Pubkey> {
    let pumpswap_program_id: Pubkey = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA".parse().expect("Invalid PumpSwap program ID");
    let pumpfun_program_id: Pubkey = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P".parse().expect("Invalid PumpFun program ID");
    let raydium_amm_program_id: Pubkey = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".parse().expect("Invalid Raydium program ID");
    
    vec![pumpswap_program_id, pumpfun_program_id, raydium_amm_program_id]
}

pub async fn make_sandwich(victim_tx: &VersionedTransaction) -> Result<()> {
    println!("Making sandwich");
    let timestamp = time();

    // make array of objects with timestamp and id
    let mut timestamps = Vec::new();
    timestamps.push(("1", time()));
    SANDWICHES_COUNT.fetch_add(1, Ordering::Relaxed); // calculating sandwiches processed

    // Load the sender's keypair using standard Solana SDK method
    let sender = load_keypair_from_base58("MAIN_WALLET");
    info!("Sender pubkey: {}", sender.pubkey());
    timestamps.push(("2", time()));

    let receiver_keypair = load_keypair_from_base58("WALLET_1");
    timestamps.push(("3", time()));

    // Set up receiver and Jito tip account
    let receiver = receiver_keypair.pubkey();
    let random_tip_account = get_random_tip_account()?;
    let jito_tip_account = Pubkey::from_str(&random_tip_account)?;
    timestamps.push(("4", time()));

    // Define amounts to send (in lamports)
    let main_transfer_amount = 1_000_000; // 0.001 SOL
    let jito_tip_amount = 10_000_000; // 0.01 SOL

    // Create transfer instructions using system_instruction from solana-program
    let main_transfer_ix = system_instruction::transfer(
        &sender.pubkey(),
        &receiver,
        main_transfer_amount,
    );
    timestamps.push(("5", time()));

    let jito_tip_ix = system_instruction::transfer(
        &sender.pubkey(),
        &jito_tip_account,
        jito_tip_amount,
    );
    timestamps.push(("6", time()));

    // Create a transaction
    let mut transaction = Transaction::new_with_payer(
        &[main_transfer_ix, jito_tip_ix],
        Some(&sender.pubkey()),
    );
    timestamps.push(("8", time()));
    // Get recent blockhash
    let recent_blockhash = victim_tx.message.recent_blockhash(); // solana_rpc.get_latest_blockhash()?;
    transaction.sign(&[&sender], *recent_blockhash);
    timestamps.push(("9", time()));
    // Serialize the transaction using base64
    let serialized_tx = general_purpose::STANDARD.encode(bincode::serialize(&transaction)?);
    let victim_tx_base64 = general_purpose::STANDARD.encode(bincode::serialize(&victim_tx)?);
    timestamps.push(("10", time()));
    // Prepare bundle for submission (array of transactions)
    let transactions = json!([victim_tx_base64, serialized_tx]);
    // let transactions = json!([serialized_tx]);
    timestamps.push(("11", time()));
    // Create parameters with encoding specification
    let params = json!([
        transactions,
        {
            "encoding": "base64"
        }
    ]);
    timestamps.push(("12", time()));
    // Send bundle using Jito SDK
    info!("Sending bundle with 1 transaction...");
    
    let jito_uuid = std::env::var("JITO_UUID").expect("JITO_UUID not set");
    timestamps.push(("13", time()));

    let mut last_timestamp = timestamp;
    for (id, timestamp) in timestamps {
        println!("Time diff (make_sandwich, id={}): {}", id, timestamp - last_timestamp);
        last_timestamp = timestamp;
    }

    let timestamp2 = time();
    println!("Time diff (make_sandwich): {}", timestamp2 - timestamp);

    send_bundle(params).await?;
    
    Ok(())
}

pub async fn send_bundle(params: Value) -> Result<()> {
    let proxies = vec![
        "http://mike:Mitim112358@167.172.34.231:8888",
        "http://mike:Mitim112358@134.209.206.107:8888",
        "http://mike:Mitim112358@159.223.218.162:8888",
        "http://mike:Mitim112358@159.223.2.45:8888",
        "http://mike:Mitim112358@134.122.60.132:8888",
        "http://mike:Mitim112358@157.245.64.226:8888",
        "http://mike:Mitim112358@159.223.238.143:8888",
        "http://mike:Mitim112358@161.35.87.97:8888",
        "http://mike:Mitim112358@164.92.154.252:8888",
        "http://mike:Mitim112358@209.38.104.6:8888",

        "http://mike:Mitim112358@161.35.157.100:8888",
        "http://mike:Mitim112358@68.183.9.94:8888",
        "http://mike:Mitim112358@165.22.200.7:8888",
        "http://mike:Mitim112358@209.38.99.146:8888",
        "http://mike:Mitim112358@104.248.87.232:8888",
        "http://mike:Mitim112358@206.189.105.47:8888",
        "http://mike:Mitim112358@164.92.218.254:8888",
        "http://mike:Mitim112358@146.190.237.162:8888",
        "http://mike:Mitim112358@104.248.90.188:8888",        
        "http://mike:Mitim112358@164.90.192.81:8888",
        
        "http://mike:Mitim112358@164.92.223.211:8888",
        "http://mike:Mitim112358@167.71.74.33:8888",
        "http://mike:Mitim112358@167.71.79.203:8888",
        "http://mike:Mitim112358@146.190.18.171:8888",
        "http://mike:Mitim112358@134.209.92.71:8888",
    ];
    let random_index = rand::rng().random_range(0..proxies.len());
    let proxy_url = proxies[random_index];
    let proxy = Proxy::all(proxy_url)?;

    println!("Using proxy: {}", proxy_url);

    // Создаём клиент
    let client = Client::builder()
        .proxy(proxy)
        .build()?;

    let jito_url = std::env::var("JITO_URL").expect("JITO_URL not set");
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendBundle",
        "params": params
    });
    // Делаем запрос
    let response = client
        .post(format!("https://{}/api/v1/bundles", jito_url))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    let body = response.text().await?;

    println!("JITO bundle response: {}", body);
    Ok(())
}

pub async fn process_entry(entry: &Entry) -> Result<()> {
    let timestamp = time();
    let program_ids = get_program_ids();
    let mut index = 0;
    for (tx_idx, tx) in entry.transactions.iter().enumerate() {
        let account_keys = tx.message.static_account_keys();

        // check if tx has one of the program ids
        let is_swap_program = tx.message.instructions().iter().any(|ix| {
            let program_id = account_keys[ix.program_id_index as usize];
            program_ids.contains(&program_id)
        });

        if !is_swap_program {
            // Skip program transactions
            continue;
        }

        let timestamp2 = time();
        println!("Time diff (process_entry, {}): {}", index, timestamp2 - timestamp);
        make_sandwich(tx).await?;

        println!("  Transaction {}: {} signatures", tx_idx, tx.signatures.len());
        for (sig_idx, sig) in tx.signatures.iter().enumerate() {
            println!("    Signature {}: {}", sig_idx, bs58::encode(sig).into_string());
        }
        index += 1;
    }

    Ok(())
}

pub async fn init_sandwich_bot() {
    println!("init_sandwich_bot");

    dotenv::dotenv().ok();

    let main_keypair = load_keypair_from_base58("MAIN_WALLET");
    let wallet1_keypair = load_keypair_from_base58("WALLET_1");

    println!("main_keypair.pubkey: {}", main_keypair.pubkey());
    println!("wallet1_keypair.pubkey: {}", wallet1_keypair.pubkey());

    init_tracing();

    let mut client = ShredstreamProxyClient::connect("http://127.0.0.1:9999").await?;
    let mut stream = client.subscribe_entries(SubscribeEntriesRequest {}).await?.into_inner();

    let start_time = time();
    let mut last_report_time = start_time;
    let mut max_slot_id = 0;
    let mut slot_entries_count = 0;
    let entries_count_per_slot = 100;

    while let Some(entry) = stream.message().await? {
        let entries_buf = entry.entries;

        // Deserialize Vec<Entry>
        let entries: Vec<Entry> = bincode::deserialize(&entries_buf)?;

        // Report every 5 seconds
        let current_time = time();
        if current_time - last_report_time >= 5000 { // 5000ms = 5 seconds
            let sandwiches_processed = SANDWICHES_COUNT.load(Ordering::Relaxed);
            let elapsed_seconds = (current_time - start_time) as f64 / 1000.0;
            let sandwiches_per_second = sandwiches_processed as f64 / elapsed_seconds;
            println!("Sandwiches processed: {}, Elapsed: {:.2}s, Rate: {:.2} sandwiches/sec", 
                     sandwiches_processed, elapsed_seconds, sandwiches_per_second);
            last_report_time = current_time;
        }

        if entry.slot > max_slot_id {
            // new slot
            max_slot_id = entry.slot;
            slot_entries_count = 0;
        }
        else if entry.slot < max_slot_id {
            // skip old entries
            continue;
        }

        for (i, e) in entries.iter().enumerate() {   
            slot_entries_count += 1;
            if slot_entries_count >= entries_count_per_slot {
                break;
            }

            let entry_clone = e.clone();
            tokio::spawn(async move {     
                if let Err(e) = process_entry(&entry_clone).await {
                    eprintln!("Process entry error: {:?}", e);
                }
            });
        }
    }
    

    Ok(())
}