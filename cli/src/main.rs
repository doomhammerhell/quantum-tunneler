use clap::{Parser, Subcommand};
use quantum_ipsec::{QuantumIpsecConfig, QuantumIpsecError};
use quantum_ipsec::ipsec::{self, SecurityAssociation};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the quantum-safe IPSec system
    Init {
        /// Security level (128, 192, or 256 bits)
        #[arg(short, long, default_value_t = 128)]
        security_level: u32,
        
        /// Maximum number of security associations
        #[arg(short, long, default_value_t = 1024)]
        max_sas: usize,
    },
    
    /// Connect to a remote endpoint
    Connect {
        /// Remote endpoint address
        #[arg(short, long)]
        remote: String,
        
        /// Local endpoint address
        #[arg(short, long)]
        local: String,
    },
    
    /// Show current status
    Status,
    
    /// Run benchmark tests
    Benchmark,
    
    /// Encrypt a payload using a given SA (hex)
    Encrypt {
        /// Security Association (hex)
        sa_hex: String,
        /// Payload (hex)
        payload_hex: String,
    },
    
    /// Decrypt a packet using a given SA (hex)
    Decrypt {
        /// Security Association (hex)
        sa_hex: String,
        /// Packet (hex)
        packet_hex: String,
    },
    
    /// Dump/parse a packet (hex)
    Dump {
        /// Packet (hex)
        packet_hex: String,
    },
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, QuantumIpsecError> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(QuantumIpsecError::PacketError("Hex string length must be even".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| QuantumIpsecError::PacketError("Invalid hex character".into())))
        .collect()
}

fn main() -> Result<(), QuantumIpsecError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { security_level, max_sas } => {
            let config = QuantumIpsecConfig {
                max_sas,
                ..Default::default()
            };
            println!("Quantum-Safe IPSec system initialized with config: {:?}", config);
            println!("Security level: {} bits", security_level);
            println!("Max SAs: {}", max_sas);
        }
        Commands::Connect { remote, local } => {
            println!("Connecting to {} from {}...", remote, local);
            // TODO: Implement connection logic
        }
        Commands::Status => {
            println!("Status: Not implemented yet");
        }
        Commands::Benchmark => {
            println!("Benchmark: Not implemented yet");
        }
        Commands::Encrypt { sa_hex, payload_hex } => {
            let sa_bytes = hex_to_bytes(&sa_hex)?;
            let payload = hex_to_bytes(&payload_hex)?;
            let sa: SecurityAssociation = bincode::deserialize(&sa_bytes)
                .map_err(|e| QuantumIpsecError::PacketError(format!("Failed to deserialize SA: {}", e)))?;
            let packet = ipsec::esp::encrypt_packet(&sa, &payload);
            let packet_bytes = bincode::serialize(&packet)
                .map_err(|e| QuantumIpsecError::PacketError(format!("Failed to serialize packet: {}", e)))?;
            println!("{}", hex::encode(packet_bytes));
        }
        Commands::Decrypt { sa_hex, packet_hex } => {
            let sa_bytes = hex_to_bytes(&sa_hex)?;
            let packet_bytes = hex_to_bytes(&packet_hex)?;
            let sa: SecurityAssociation = bincode::deserialize(&sa_bytes)
                .map_err(|e| QuantumIpsecError::PacketError(format!("Failed to deserialize SA: {}", e)))?;
            let packet: ipsec::esp::EspPacket = bincode::deserialize(&packet_bytes)
                .map_err(|e| QuantumIpsecError::PacketError(format!("Failed to deserialize packet: {}", e)))?;
            let result = ipsec::esp::decrypt_packet(&sa, &packet)?;
            println!("{}", hex::encode(result));
        }
        Commands::Dump { packet_hex } => {
            let packet_bytes = hex_to_bytes(&packet_hex)?;
            let packet: ipsec::esp::EspPacket = bincode::deserialize(&packet_bytes)
                .map_err(|e| QuantumIpsecError::PacketError(format!("Failed to deserialize packet: {}", e)))?;
            println!("{:#?}", packet);
        }
    }

    Ok(())
} 