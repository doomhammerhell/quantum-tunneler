use clap::{Parser, Subcommand};
use quantum_ipsec::{init, QuantumIpsecConfig, QuantumIpsecError};

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
}

fn main() -> Result<(), QuantumIpsecError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { security_level, max_sas } => {
            let config = QuantumIpsecConfig {
                security_level,
                max_sas,
                ..Default::default()
            };
            init(config)?;
            println!("Quantum-Safe IPSec system initialized successfully");
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
    }

    Ok(())
} 