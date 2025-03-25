use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chrono::Utc;
use clap::Parser;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use block_padding::Pkcs7;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Parser, Debug)]
#[clap(about = "Blockchain P2P Server")]
struct Args {
    #[clap(short = 'p', long, default_value = "8080")]
    port: String,
    #[clap(short = 'e', long, default_value = "")]
    peers: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncryptionKeys {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    aes_key: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TransactionRecord {
    tx_id: String,
    counterparty: String,
    amount: i64,
    timestamp: i64,
    block_height: Option<u64>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
enum SmartContract {
    GetBalance {
        id: String,
        address: String,
        requester: String,
    },
    Transfer {
        id: String,
        sender: String,
        receiver: String,
        amount: u64,
        password: String,
    },
    GetTransactionHistory {
        id: String,
        address: String,
        requester: String,
    },
    GrantAccess {
        id: String,
        account: String,
        granter: String,
        grantee: String,
        rights: Vec<AccessRight>,
        duration_seconds: Option<u64>,
        password: String,
    },
    RevokeAccess {
        id: String,
        account: String,
        revoker: String,
        grant_id: String,
        password: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Blockchain {
    chain: Vec<Block>,
    pending_transactions: Vec<Transaction>,
    accounts: HashMap<String, Account>,
    staked_tokens: HashMap<String, u64>,
    executed_contracts: HashSet<String>,
    #[serde(skip_serializing, skip_deserializing)]
    encryption_keys: Option<EncryptionKeys>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AccessRight {
    ViewBalance,
    ViewTransactions,
    GrantAccess,
    RevokeAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    pub id: String,
    pub grantee: String,
    pub rights: HashSet<AccessRight>,
    pub expires_at: Option<i64>,
    pub granted_at: i64,
    pub granted_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountGuard {
    owner: String,
    active_grants: HashMap<String, AccessGrant>,
    revoked_grants: HashSet<String>,
    password_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Account {
    balance: u64,
    transaction_history: Vec<TransactionRecord>,
    guard: AccountGuard,
}

impl EncryptionKeys {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate private key");
        let public_key = RsaPublicKey::from(&private_key);
        
        Self {
            public_key: public_key.to_pkcs1_der().unwrap().as_bytes().to_vec(),
            private_key: private_key.to_pkcs1_der().unwrap().as_bytes().to_vec(),
            aes_key: None,
        }
    }
    
    fn generate_aes_key(&mut self) -> Vec<u8> {
        let key: [u8; 32] = rand::random();
        self.aes_key = Some(key.to_vec());
        key.to_vec()
    }
    
    fn encrypt_with_rsa(&self, data: &[u8]) -> Vec<u8> {
        let public_key = RsaPublicKey::from_pkcs1_der(&self.public_key).unwrap();
        let mut rng = rand::thread_rng();
        public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
            .expect("RSA encryption failed")
    }
    
    fn decrypt_with_rsa(&self, data: &[u8]) -> Vec<u8> {
        let private_key = RsaPrivateKey::from_pkcs1_der(&self.private_key).unwrap();
        private_key.decrypt(Pkcs1v15Encrypt, data)
            .expect("RSA decryption failed")
    }
    
    fn encrypt_with_aes(&self, data: &[u8]) -> Vec<u8> {
        let key = self.aes_key.as_ref().expect("AES key not initialized");
        let iv: [u8; 16] = rand::random();
        
        let cipher = Aes256CbcEnc::new_from_slices(key, &iv).expect("Invalid key/iv length");
        let mut buffer = iv.to_vec();
        buffer.extend(cipher.encrypt_padded_vec_mut::<block_padding::Pkcs7>(data));
        buffer
    }
    
    fn decrypt_with_aes(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 16 {
            panic!("Invalid encrypted data length");
        }
        
        let key = self.aes_key.as_ref().expect("AES key not initialized");
        let iv = &data[..16];
        let cipher = Aes256CbcDec::new_from_slices(key, iv).expect("Invalid key/iv length");
        
        cipher.decrypt_padded_vec_mut::<block_padding::Pkcs7>(&data[16..])
            .expect("Decryption failed")
    }
}

impl AccountGuard {
    fn new(owner: &str, password: &str) -> Self {
        Self {
            owner: owner.to_string(),
            active_grants: HashMap::new(),
            revoked_grants: HashSet::new(),
            password_hash: hash_password(password),
        }
    }

    fn grant_access(
        &mut self,
        granter: &str,
        grantee: &str,
        rights: Vec<AccessRight>,
        duration: Option<std::time::Duration>,
    ) -> Result<String, String> {
        if granter != self.owner {
            self.check_access(granter, &AccessRight::GrantAccess)?;
        }

        let grant_id = Uuid::new_v4().to_string();
        let expires_at = duration.map(|d| Utc::now().timestamp() + d.as_secs() as i64);

        let grant = AccessGrant {
            id: grant_id.clone(),
            grantee: grantee.to_string(),
            rights: rights.into_iter().collect(),
            expires_at,
            granted_at: Utc::now().timestamp(),
            granted_by: granter.to_string(),
        };

        self.active_grants.insert(grant_id.clone(), grant);
        Ok(grant_id)
    }

    fn revoke_access(&mut self, revoker: &str, grant_id: &str) -> Result<(), String> {
        let grant = self.active_grants.get(grant_id)
            .ok_or("Grant not found")?;

        if revoker != self.owner && revoker != grant.granted_by {
            return Err("Unauthorized revocation attempt".into());
        }

        self.revoked_grants.insert(grant_id.to_string());
        self.active_grants.remove(grant_id);
        Ok(())
    }

    fn check_access(&self, requester: &str, right: &AccessRight) -> Result<(), String> {
        if requester == self.owner {
            return Ok(());
        }

        for grant in self.active_grants.values() {
            if grant.grantee == requester &&
               !self.revoked_grants.contains(&grant.id) &&
               grant.rights.contains(right) &&
               grant.expires_at.map_or(true, |exp| exp > Utc::now().timestamp())
            {
                return Ok(());
            }
        }

        Err(format!("Missing {:?} access rights", right))
    }

    fn verify_password(&self, password: &str) -> bool {
        hash_password(password) == self.password_hash
    }
}

impl Block {
    fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let mut block = Self {
            index,
            timestamp: Utc::now().timestamp(),
            transactions,
            previous_hash,
            hash: String::new(),
            nonce: 0,
        };
        block.hash = block.calculate_hash();
        block
    }

    fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(self).unwrap());
        format!("{:x}", hasher.finalize())
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartContract {
    fn id(&self) -> &str {
        match self {
            Self::GetBalance { id, .. } => id,
            Self::Transfer { id, .. } => id,
            Self::GetTransactionHistory { id, .. } => id,
            Self::GrantAccess { id, .. } => id,
            Self::RevokeAccess { id, .. } => id,
        }
    }
}

impl Blockchain {
    fn new() -> Self {
        let mut bc = Self {
            chain: Vec::new(),
            pending_transactions: Vec::new(),
            accounts: HashMap::new(),
            staked_tokens: HashMap::new(),
            executed_contracts: HashSet::new(),
            encryption_keys: None,
        };
        bc.create_genesis_block();
        bc
    }

    fn encrypt_data(&self, data: &[u8]) -> Vec<u8> {
        if let Some(keys) = &self.encryption_keys {
            if keys.aes_key.is_some() {
                return keys.encrypt_with_aes(data);
            }
        }
        data.to_vec()
    }

    fn decrypt_data(&self, data: &[u8]) -> Vec<u8> {
        if let Some(keys) = &self.encryption_keys {
            if keys.aes_key.is_some() {
                return keys.decrypt_with_aes(data);
            }
        }
        data.to_vec()
    }

    fn create_genesis_block(&mut self) {
        self.chain.push(Block::new(0, Vec::new(), "0".into()));
    }

    fn execute_smart_contract(&mut self, contract: SmartContract) -> String {
        let contract_id = contract.id().to_string();
        if !self.executed_contracts.insert(contract_id.clone()) {
            return format!("Contract {} already executed", contract_id);
        }

        match contract {
            SmartContract::GetBalance { address, requester, .. } => 
                self.handle_balance_check(address, requester),
            SmartContract::GetTransactionHistory { address, requester, .. } => {
                match self.get_transaction_history(&address, &requester) {
                    Some(history) => serde_json::to_string(&history).unwrap_or_default(),
                    None => "Invalid credentials or account not found".into(),
                }
            }
            SmartContract::Transfer { sender, receiver, amount, password, .. } => 
                self.handle_transfer(sender, receiver, amount, password),
            SmartContract::GrantAccess { account, granter, grantee, rights, duration_seconds, password, .. } => {
                let duration = duration_seconds.map(|s| std::time::Duration::from_secs(s));
                self.handle_grant_access(account, granter, grantee, rights, duration, password)
            }
            SmartContract::RevokeAccess { account, revoker, grant_id, password, .. } => 
                self.handle_revoke_access(account, revoker, grant_id, password),
        }
    }

    fn handle_balance_check(&self, address: String, requester: String) -> String {
        match self.accounts.get(&address) {
            Some(acc) => match acc.guard.check_access(&requester, &AccessRight::ViewBalance) {
                Ok(_) => format!("Balance: {}", acc.balance),
                Err(e) => e,
            },
            None => "Account not found".into(),
        }
    }

    fn get_transaction_history(&self, address: &str, requester: &str) -> Option<Vec<TransactionRecord>> {
        self.accounts.get(address).and_then(|acc| {
            acc.guard.check_access(requester, &AccessRight::ViewTransactions)
                .ok()
                .map(|_| acc.transaction_history.clone())
        })
    }

    fn handle_transfer(&mut self, sender: String, receiver: String, amount: u64, password: String) -> String {
        if sender == "0" {
            let tx_id = Uuid::new_v4().to_string();
            let timestamp = Utc::now().timestamp();
            let block_height = self.chain.len() as u64;
            
            let record = TransactionRecord {
                tx_id,
                counterparty: "system".to_string(),
                amount: amount as i64,
                timestamp,
                block_height: Some(block_height),
            };

            self.accounts.entry(receiver.clone())
                .and_modify(|acc| {
                    acc.balance += amount;
                    acc.transaction_history.push(record.clone());
                })
                .or_insert(Account {
                    balance: amount,
                    transaction_history: vec![record],
                    guard: AccountGuard::new(&receiver, ""),
                });
            
            return format!("Mined {} tokens to {}", amount, receiver);
        }

        match self.accounts.get_mut(&sender) {
            Some(acc) if acc.guard.verify_password(&password) => {
                if acc.balance < amount {
                    return format!("Insufficient balance: {}", acc.balance);
                }
                
                let tx_id = Uuid::new_v4().to_string();
                let timestamp = Utc::now().timestamp();
                let block_height = self.chain.len() as u64;

                acc.balance -= amount;
                acc.transaction_history.push(TransactionRecord {
                    tx_id: tx_id.clone(),
                    counterparty: receiver.clone(),
                    amount: -(amount as i64),
                    timestamp,
                    block_height: Some(block_height),
                });

                self.accounts.entry(receiver.clone())
                    .and_modify(|acc| {
                        acc.balance += amount;
                        acc.transaction_history.push(TransactionRecord {
                            tx_id: tx_id.clone(),
                            counterparty: sender.clone(),
                            amount: amount as i64,
                            timestamp,
                            block_height: Some(block_height),
                        });
                    })
                    .or_insert(Account {
                        balance: amount,
                        transaction_history: vec![TransactionRecord {
                            tx_id,
                            counterparty: sender.clone(),
                            amount: amount as i64,
                            timestamp,
                            block_height: Some(block_height),
                        }],
                        guard: AccountGuard::new(&receiver, ""),
                    });

                self.save_to_file("blockchain.json").unwrap();
                format!("Transferred {} from {} to {}", amount, sender, receiver)
            }
            Some(_) => "Invalid password".into(),
            None => "Sender account not found".into(),
        }
    }

    fn handle_grant_access(
        &mut self,
        account: String,
        granter: String,
        grantee: String,
        rights: Vec<AccessRight>,
        duration: Option<std::time::Duration>,
        password: String,
    ) -> String {
        match self.accounts.get_mut(&account) {
            Some(acc) => {
                if !acc.guard.verify_password(&password) {
                    return "Invalid password".into();
                }
                match acc.guard.grant_access(&granter, &grantee, rights, duration) {
                    Ok(id) => format!("Access granted with ID: {}", id),
                    Err(e) => e,
                }
            }
            None => "Account not found".into(),
        }
    }

    fn handle_revoke_access(
        &mut self,
        account: String,
        revoker: String,
        grant_id: String,
        password: String,
    ) -> String {
        match self.accounts.get_mut(&account) {
            Some(acc) => {
                if !acc.guard.verify_password(&password) {
                    return "Invalid password".into();
                }
                match acc.guard.revoke_access(&revoker, &grant_id) {
                    Ok(_) => "Access revoked successfully".into(),
                    Err(e) => e,
                }
            }
            None => "Account not found".into(),
        }
    }

    fn save_to_file(&self, filename: &str) -> std::io::Result<()> {
        let mut bc_for_serialization = self.clone();
        bc_for_serialization.encryption_keys = None;
        
        let serialized = serde_json::to_string_pretty(&bc_for_serialization)?;
        let encrypted = self.encrypt_data(serialized.as_bytes());
        fs::write(filename, encrypted)
    }

    fn load_from_file(filename: &str, encryption_keys: Option<EncryptionKeys>) -> std::io::Result<Self> {
        let encrypted = fs::read(filename)?;
        
        if encrypted.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Empty file",
            ));
        }

        let temp_bc = Blockchain {
            encryption_keys,
            ..Default::default()
        };
        
        let decrypted = temp_bc.decrypt_data(&encrypted);
        let decrypted_str = String::from_utf8(decrypted)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        
        let mut blockchain: Blockchain = serde_json::from_str(&decrypted_str)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        blockchain.encryption_keys = temp_bc.encryption_keys;
        Ok(blockchain)
    }
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password);
    format!("{:x}", hasher.finalize())
}

async fn handle_connection(mut stream: tokio::net::TcpStream, blockchain: Arc<Mutex<Blockchain>>) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer).await {
        Ok(n) if n > 0 => {
            let message = String::from_utf8_lossy(&buffer[..n]);
            let response = match serde_json::from_str::<SmartContract>(&message) {
                Ok(contract) => blockchain.lock().unwrap().execute_smart_contract(contract),
                Err(e) => format!("Invalid contract: {}", e),
            };

            if let Err(e) = stream.write_all(response.as_bytes()).await {
                eprintln!("Failed to send response: {}", e);
            }
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    
    let mut encryption_keys = EncryptionKeys::new();
    encryption_keys.generate_aes_key();

    let blockchain = match Blockchain::load_from_file("blockchain.json", Some(encryption_keys)) {
        Ok(bc) => bc,
        Err(_) => {
            let mut new_bc = Blockchain::new();
            new_bc.encryption_keys = Some(EncryptionKeys::new());
            new_bc.encryption_keys.as_mut().unwrap().generate_aes_key();
            
            new_bc.accounts.insert("alice.wallet".into(), Account {
                balance: 1000,
                transaction_history: Vec::new(),
                guard: AccountGuard::new("alice.wallet", "alice123"),
            });
            new_bc.accounts.insert("bob.wallet".into(), Account {
                balance: 500,
                transaction_history: Vec::new(),
                guard: AccountGuard::new("bob.wallet", "bob123"),
            });
            new_bc.save_to_file("blockchain.json").unwrap();
            new_bc
        }
    };

    let blockchain = Arc::new(Mutex::new(blockchain));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port)).await?;
    
    println!("Server running on port {}", args.port);
    
    loop {
        let (stream, _) = listener.accept().await?;
        let blockchain = blockchain.clone();
        tokio::spawn(async move {
            handle_connection(stream, blockchain).await;
        });
    }
}
/*
{
  "GrantAccess": {
    "id": "unique-id-123",
    "account": "alice.wallet",
    "granter": "alice.wallet",
    "grantee": "bob.wallet",
    "rights": ["ViewBalance"],
    "duration_seconds": 86400,
    "password": "alice123"
  }
}

{
  "GetBalance": {
    "id": "unique-id-456",
    "address": "alice.wallet",
    "requester": "bob.wallet"
  }
}

{
  "RevokeAccess": {
    "id": "unique-id-789",
    "account": "alice.wallet",
    "revoker": "alice.wallet",
    "grant_id": "grant-id-from-response",
    "password": "alice123"
  }
}

*/
