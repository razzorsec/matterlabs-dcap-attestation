use std::process::Command;
use reqwest;
use serde_json::Value;
use std::env;

const CONTRACT_ADDRESS: &str = "0xYourContractAddress";
const RPC_URL: &str = "https://your-rpc-url"; 
const PRIVATE_KEY: &str = "your-private-key"; 

#[tokio::main]
async fn main() {
    match fetch_hashes_from_tee().await {
        Ok((enclave_hashes, td10_hashes, rt_mr_hashes)) => {
            call_contract("addValidEnclaveHashes", &enclave_hashes);
            call_contract("addValidTD10MrTDHashes", &td10_hashes);
            call_contract("addValidRtMrHashes", &rt_mr_hashes);
        }
        Err(e) => eprintln!("Error fetching hashes from TEE: {}", e),
    }
}

async fn fetch_hashes_from_tee() -> Result<(Vec<String>, Vec<String>, Vec<String>), reqwest::Error> {
    let response = reqwest::get("https://tee.example.com/get_hashes").await?; 
    let json: Value = response.json().await?;

    let enclave_hashes = json["enclave_hashes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let td10_hashes = json["td10_hashes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let rt_mr_hashes = json["rt_mr_hashes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    Ok((enclave_hashes, td10_hashes, rt_mr_hashes))
}

fn call_contract(function: &str, hashes: &Vec<String>) {
    if hashes.is_empty() {
        println!("No hashes to send for {}", function);
        return;
    }

    let hashes_str = hashes
        .iter()
        .map(|h| format!("\"{}\"", h))
        .collect::<Vec<_>>()
        .join(",");

    let command = format!(
        "cast send {} \"{}(bytes32[])\" [{}] --rpc-url {} --private-key {}",
        CONTRACT_ADDRESS, function, hashes_str, RPC_URL, PRIVATE_KEY
    );

    println!("Executing: {}", command);

    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("Failed to execute cast send");

    if output.status.success() {
        println!("Transaction sent successfully: {:?}", output);
    } else {
        eprintln!("Error sending transaction: {:?}", output);
    }
}
