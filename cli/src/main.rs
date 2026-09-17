mod commands;
mod utils;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "quantum-ipsec",
    version,
    about = "Experimental IPsec hardening laboratory (no live tunnel support)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(long, global = true)]
    pub config: Option<String>,
    #[arg(long, global = true)]
    pub verbose: bool,
    #[arg(long, global = true)]
    pub quiet: bool,
    #[arg(long, global = true, default_value = "text")]
    pub output_format: String,
}

#[derive(Subcommand)]
pub enum Commands {
    Init(commands::init::InitArgs),
    Connect(commands::connect::ConnectArgs),
    Status(commands::status::StatusArgs),
    Encrypt(commands::encrypt::EncryptArgs),
    Decrypt(commands::decrypt::DecryptArgs),
    Benchmark(commands::benchmark::BenchmarkArgs),
    Config(commands::config::ConfigArgs),
    Monitor(commands::monitor::MonitorArgs),
}

#[tokio::main]
async fn main() -> Result<(), utils::CliError> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Init(args) => commands::init::run(args.clone(), &cli).await,
        Commands::Connect(args) => commands::connect::run(args.clone(), &cli).await,
        Commands::Status(args) => commands::status::run(args.clone(), &cli).await,
        Commands::Encrypt(args) => commands::encrypt::run(args.clone(), &cli).await,
        Commands::Decrypt(args) => commands::decrypt::run(args.clone(), &cli).await,
        Commands::Benchmark(args) => commands::benchmark::run(args.clone(), &cli).await,
        Commands::Config(args) => commands::config::run(args.clone(), &cli).await,
        Commands::Monitor(args) => commands::monitor::run(args.clone(), &cli).await,
    }
}
