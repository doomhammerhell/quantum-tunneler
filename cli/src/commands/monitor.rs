use clap::Args;
use crate::utils::CliError;
use std::time::{Duration, Instant};
use std::io;
use crossterm::{event, execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{prelude::*, widgets::*};
use quantum_ipsec::{IpSecProcessor, QuantumIpsecConfig};

/// Monitor IPSec state in a TUI dashboard
#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    /// Refresh interval in ms
    #[arg(long, default_value = "1000")]
    pub interval: u64,
}

pub async fn run(args: MonitorArgs, _global: &crate::Cli) -> Result<(), CliError> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let refresh = Duration::from_millis(args.interval);
    let start = Instant::now();
    let mut last_tick = Instant::now();

    loop {
        // Simula leitura de estado
        let config = QuantumIpsecConfig::default();
        let ipsec = IpSecProcessor::new().map_err(CliError::from)?;
        let stats = ipsec.get_stats();

        terminal.draw(|f| {
            let size = f.size();
            let block = Block::default().title("Quantum-IPSec Monitor").borders(Borders::ALL);
            f.render_widget(block, size);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                ])
                .split(size);

            let stats_table = Table::new(vec![
                Row::new(vec!["Packets", &stats.packets_processed.to_string()]),
                Row::new(vec!["ESP Packets", &stats.esp_packets.to_string()]),
                Row::new(vec!["AH Packets", &stats.ah_packets.to_string()]),
                Row::new(vec!["Auth Failures", &stats.auth_failures.to_string()]),
                Row::new(vec!["Crypto Failures", &stats.crypto_failures.to_string()]),
                Row::new(vec!["Policy Matches", &stats.policy_matches.to_string()]),
            ])
            .header(Row::new(vec!["Stat", "Value"]))
            .block(Block::default().borders(Borders::ALL).title("IPSec Stats"))
            .widths(&[Constraint::Length(20), Constraint::Length(10)]);

            f.render_widget(stats_table, chunks[1]);
        })?;

        let timeout = refresh
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let event::Event::Key(key) = event::read()? {
                if key.code == event::KeyCode::Char('q') {
                    break;
                }
            }
        }
        if last_tick.elapsed() >= refresh {
            last_tick = Instant::now();
        }
    }
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
} 