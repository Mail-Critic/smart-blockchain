use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use chrono::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::Rng;
use std::fs;
use std::path::Path;
use clap::Parser;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[clap(about = "A simple blockchain P2P server")]
struct Args {
    /// Port to listen on
    #[clap(short = 'p', long, default_value = "8080")]
    port: String,

    /// Comma-separated list of peer addresses
    #[clap(short = 'e', long, default_value = "")]
    peers: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: u64,
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    timestamp: i64,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
    nonce: u64,
}

impl Block {
    fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Block {
        let timestamp = Utc::now().timestamp();
        let mut block = Block {
            index,
            timestamp,
            transactions,
            previous_hash,
            hash: String::new(),
            nonce: 0,
        };
        block.hash = block.calculate_hash();
        block
    }

    fn calculate_hash(&self) -> String {
        let input = format!(
            "{}{}{:?}{}{}",
            self.index, self.timestamp, self.transactions, self.previous_hash, self.nonce
        );
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Blockchain {
    chain: Vec<Block>,
    pending_transactions: Vec<Transaction>,
    accounts: HashMap<String, u64>,
    staked_tokens: HashMap<String, u64>,
    executed_contracts: HashSet<String>,
}

impl Blockchain {
    fn new() -> Blockchain {
        let mut blockchain = Blockchain {
            chain: Vec::new(),
            pending_transactions: Vec::new(),
            accounts: HashMap::new(),
            staked_tokens: HashMap::new(),
            executed_contracts: HashSet::new(),
        };
        blockchain.create_genesis_block();
        blockchain
    }

    fn create_genesis_block(&mut self) {
        let genesis_block = Block::new(0, Vec::new(), "0".to_string());
        self.chain.push(genesis_block);
    }

    fn add_transaction(&mut self, sender: String, receiver: String, amount: u64, signature: Vec<u8>) {
        let transaction = Transaction {
            sender,
            receiver,
            amount,
            signature,
        };
        self.pending_transactions.push(transaction);
    }

    fn stake_tokens(&mut self, staker: String, amount: u64) {
        if self.get_balance(&staker) >= amount {
            self.accounts.entry(staker.clone()).and_modify(|balance| *balance -= amount);
            self.staked_tokens.entry(staker.clone()).and_modify(|stake| *stake += amount).or_insert(amount);
            println!("Staked: {} tokens by {}", amount, staker);
        } else {
            println!("Staking failed: Insufficient balance for {}", staker);
        }
    }

    fn select_validator(&self) -> Option<String> {
        let total_stake: u64 = self.staked_tokens.values().sum();
        if total_stake == 0 {
            return None;
        }

        let mut rng = rand::thread_rng();
        let random_stake: u64 = rng.gen_range(0..total_stake);
        let mut cumulative_stake = 0;

        for (staker, stake) in &self.staked_tokens {
            cumulative_stake += stake;
            if cumulative_stake >= random_stake {
                return Some(staker.clone());
            }
        }
        None
    }

    fn mine_pending_transactions(&mut self, miner_address: String) {
        if let Some(validator) = self.select_validator() {
            if validator == miner_address {
                let reward_transaction = Transaction {
                    sender: "0".to_string(),
                    receiver: miner_address.clone(),
                    amount: 50,
                    signature: Vec::new(),
                };
                self.pending_transactions.push(reward_transaction);

                let mut block = Block::new(
                    self.chain.len() as u64,
                    self.pending_transactions.clone(),
                    self.chain.last().unwrap().hash.clone(),
                );
                block.hash = block.calculate_hash();
                self.chain.push(block);
                self.pending_transactions.clear();
                self.executed_contracts.clear();
                println!("Block validated by: {}", miner_address);
            } else {
                println!("Mining failed: {} is not the selected validator", miner_address);
            }
        } else {
            println!("Mining failed: No validators available");
        }
    }

    fn get_balance(&self, address: &str) -> u64 {
        *self.accounts.get(address).unwrap_or(&0)
    }

    fn save_to_file(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(filename, data)?;
        Ok(())
    }

    fn load_from_file(filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(filename)?;
        let blockchain: Blockchain = serde_json::from_str(&data)?;
        Ok(blockchain)
    }

    fn execute_smart_contract(&mut self, contract: SmartContract) {
        let contract_id = match &contract {
            SmartContract::Transfer { id, .. } => id,
            SmartContract::Escrow { id, .. } => id,
            SmartContract::Staking { id, .. } => id,
            SmartContract::ReleaseEscrow { id, .. } => id,
        };

        if self.executed_contracts.contains(contract_id) {
            println!("Contract already executed: {}", contract_id);
            return;
        }

        self.executed_contracts.insert(contract_id.clone());

        match contract {
            SmartContract::Transfer { sender, receiver, amount, .. } => {
                if self.get_balance(&sender) >= amount {
                    self.accounts.entry(sender.clone()).and_modify(|balance| *balance -= amount);
                    self.accounts.entry(receiver.clone()).and_modify(|balance| *balance += amount);
                    println!("Transfer: {} tokens sent from {} to {}", amount, sender, receiver);
                } else {
                    println!("Transfer failed: Insufficient balance for {}", sender);
                }
            }
            SmartContract::Escrow { sender, receiver, arbiter: _, amount, released: _, .. } => {
                if self.get_balance(&sender) >= amount {
                    self.accounts.entry(sender.clone()).and_modify(|balance| *balance -= amount);
                    println!("Escrow: {} tokens held in escrow from {} to {}", amount, sender, receiver);
                    self.pending_transactions.push(Transaction {
                        sender,
                        receiver,
                        amount,
                        signature: Vec::new(),
                    });
                } else {
                    println!("Escrow failed: Insufficient balance for {}", sender);
                }
            }
            SmartContract::Staking { staker, amount, duration, .. } => {
                if self.get_balance(&staker) >= amount {
                    self.stake_tokens(staker, amount);
                    println!("Staking: {} tokens staked for {} blocks", amount, duration);
                } else {
                    println!("Staking failed: Insufficient balance for {}", staker);
                }
            }
            SmartContract::ReleaseEscrow { escrow_id, arbiter, .. } => {
                println!("Escrow {} released by arbiter {}", escrow_id, arbiter);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum SmartContract {
    Transfer {
        id: String,
        sender: String,
        receiver: String,
        amount: u64,
    },
    Escrow {
        id: String,
        sender: String,
        receiver: String,
        arbiter: String,
        amount: u64,
        released: bool,
    },
    Staking {
        id: String,
        staker: String,
        amount: u64,
        duration: u64,
    },
    ReleaseEscrow {
        id: String,
        escrow_id: usize,
        arbiter: String,
    },
}

async fn broadcast_message(message: &str, peers: Vec<String>) {
    for peer in peers {
        let message = message.to_string();
        tokio::spawn(async move {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(&peer).await {
                if let Err(e) = stream.write_all(message.as_bytes()).await {
                    eprintln!("Failed to send message to {}: {}", peer, e);
                }
            } else {
                eprintln!("Failed to connect to peer: {}", peer);
            }
        });
    }
}

async fn start_p2p_server(blockchain: Arc<Mutex<Blockchain>>, peers: Vec<String>, port: &str) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
    println!("P2P server started on 127.0.0.1:{}", port);

    let seen_messages = Arc::new(Mutex::new(HashSet::new()));

    loop {
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let blockchain = blockchain.clone();
                let peers = peers.clone();
                let seen_messages = seen_messages.clone();
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => {
                                let message = String::from_utf8_lossy(&buf[..n]);
                                println!("Received raw message: {}", message);

                                let message_id = match serde_json::from_str::<SmartContract>(&message) {
                                    Ok(SmartContract::Transfer { id, .. }) => id,
                                    Ok(SmartContract::Escrow { id, .. }) => id,
                                    Ok(SmartContract::Staking { id, .. }) => id,
                                    Ok(SmartContract::ReleaseEscrow { id, .. }) => id,
                                    Err(_) => {
                                        let mut hasher = Sha256::new();
                                        hasher.update(&*message);
                                        format!("{:x}", hasher.finalize())
                                    }
                                };

                                {
                                    let mut seen = seen_messages.lock().unwrap();
                                    if seen.contains(&message_id) {
                                        println!("Duplicate message detected, skipping: {}", message_id);
                                        continue;
                                    }
                                    seen.insert(message_id.clone());
                                }

                                match serde_json::from_str::<SmartContract>(&message) {
                                    Ok(contract) => {
                                        let contract_clone = contract.clone();
                                        {
                                            let mut blockchain = blockchain.lock().unwrap();
                                            blockchain.execute_smart_contract(contract);
                                            blockchain.save_to_file("blockchain.json").unwrap_or_else(|e| {
                                                eprintln!("Failed to save blockchain to file: {}", e);
                                            });
                                        }

                                        let response = "Message received and processed";
                                        if let Err(e) = socket.write_all(response.as_bytes()).await {
                                            eprintln!("Failed to send response: {}", e);
                                        }

                                        let serialized_contract = serde_json::to_string(&contract_clone).unwrap();
                                        let peers_clone = peers.clone();
                                        tokio::spawn(async move {
                                            broadcast_message(&serialized_contract, peers_clone).await;
                                        });
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to deserialize message: {}", e);
                                        let response = format!("Failed to process message: {}", e);
                                        if let Err(e) = socket.write_all(response.as_bytes()).await {
                                            eprintln!("Failed to send error response: {}", e);
                                        }
                                    }
                                }
                            }
                            Ok(_) => break,
                            Err(e) => {
                                eprintln!("Failed to read from socket: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("Failed to accept connection: {}", e),
        }
    }
}

fn load_or_create_blockchain(filename: &str) -> Blockchain {
    if Path::new(filename).exists() {
        println!("Loading blockchain from file: {}", filename);
        Blockchain::load_from_file(filename).unwrap_or_else(|_| {
            println!("Failed to load blockchain from file. Creating a new one.");
            let mut blockchain = Blockchain::new();
            initialize_default_wallets(&mut blockchain);
            blockchain
        })
    } else {
        println!("Creating a new blockchain with default wallets.");
        let mut blockchain = Blockchain::new();
        initialize_default_wallets(&mut blockchain);
        blockchain.save_to_file(filename).unwrap_or_else(|e| {
            println!("Failed to save blockchain to file: {}", e);
        });
        blockchain
    }
}

fn initialize_default_wallets(blockchain: &mut Blockchain) {
    blockchain.accounts.insert("alice.wallet".to_string(), 1000);
    blockchain.accounts.insert("bob.wallet".to_string(), 500);
    blockchain.accounts.insert("miner.wallet".to_string(), 0);
    println!("Initialized default wallets with balances.");
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let filename = "blockchain.json";
    let blockchain = Arc::new(Mutex::new(load_or_create_blockchain(filename)));

    let peers: Vec<String> = if args.peers.is_empty() {
        Vec::new()
    } else {
        args.peers.split(',').map(|s| s.to_string()).collect()
    };

    let blockchain_clone = blockchain.clone();
    let peers_clone = peers.clone();
    tokio::spawn(async move {
        start_p2p_server(blockchain_clone, peers_clone, &args.port).await;
    });

    let alice_address = "alice.wallet".to_string();
    let bob_address = "bob.wallet".to_string();
    let miner_address = "miner.wallet".to_string();

    blockchain.lock().unwrap().stake_tokens(miner_address.clone(), 100);

    let transfer_contract = SmartContract::Transfer {
        id: Uuid::new_v4().to_string(),
        sender: alice_address.clone(),
        receiver: bob_address.clone(),
        amount: 100,
    };

    blockchain.lock().unwrap().execute_smart_contract(transfer_contract);

    let staking_contract = SmartContract::Staking {
        id: Uuid::new_v4().to_string(),
        staker: bob_address.clone(),
        amount: 200,
        duration: 100,
    };

    blockchain.lock().unwrap().execute_smart_contract(staking_contract);

    blockchain.lock().unwrap().mine_pending_transactions(miner_address.clone());

    println!("Alice's balance: {}", blockchain.lock().unwrap().get_balance(&alice_address));
    println!("Bob's balance: {}", blockchain.lock().unwrap().get_balance(&bob_address));

    blockchain.lock().unwrap().save_to_file(filename).unwrap_or_else(|e| {
        println!("Failed to save blockchain to file: {}", e);
    });

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

//How to run
//cargo run -- --port 8080 --peers 127.0.0.1:8081,127.0.0.1:8082
//cargo run -- --port 8081 --peers 127.0.0.1:8080,127.0.0.1:8082
//cargo run -- --port 8082 --peers 127.0.0.1:8080,127.0.0.1:8081
//echo '{"Transfer":{"id":"550e8400-e29b-41d4-a716-4466554400004","sender":"bob.wallet","receiver":"alice.wallet","amount":10}}' | nc 127.0.0.1 8080
 