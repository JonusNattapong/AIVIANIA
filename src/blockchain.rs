//! Blockchain module for interacting with Ethereum blockchain.
//!
//! Provides functionality to connect to Ethereum nodes and perform basic operations.

use std::str::FromStr;
use web3::transports::Http;
use web3::types::{Address, U256, U64};
use web3::Web3;

/// Blockchain client for Ethereum interactions.
pub struct BlockchainClient {
    web3: Web3<Http>,
}

impl BlockchainClient {
    /// Create a new blockchain client with the given RPC URL.
    pub fn new(rpc_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let transport = Http::new(rpc_url)?;
        let web3 = Web3::new(transport);
        Ok(Self { web3 })
    }

    /// Get the balance of an Ethereum address.
    pub async fn get_balance(
        &self,
        address: &str,
    ) -> Result<U256, Box<dyn std::error::Error + Send + Sync>> {
        let addr = Address::from_str(address)?;
        let balance = self.web3.eth().balance(addr, None).await?;
        Ok(balance)
    }

    /// Get the current block number.
    pub async fn get_block_number(&self) -> Result<U64, Box<dyn std::error::Error + Send + Sync>> {
        let block_number = self.web3.eth().block_number().await?;
        Ok(block_number)
    }

    /// Check if an address is a contract.
    pub async fn is_contract(
        &self,
        address: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let addr = Address::from_str(address)?;
        let code = self.web3.eth().code(addr, None).await?;
        Ok(!code.0.is_empty())
    }
}

/// Blockchain plugin for integration with the application.
pub struct BlockchainPlugin {
    client: Option<BlockchainClient>,
}

impl BlockchainPlugin {
    pub fn new(rpc_url: Option<&str>) -> Self {
        let client = rpc_url.and_then(|url| BlockchainClient::new(url).ok());
        Self { client }
    }

    pub fn client(&self) -> Option<&BlockchainClient> {
        self.client.as_ref()
    }
}

impl crate::plugin::Plugin for BlockchainPlugin {
    fn name(&self) -> &'static str {
        "blockchain"
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn init(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
                + Send,
        >,
    > {
        Box::pin(async { Ok(()) })
    }
}
