use crate::utils::{print_output, CliError};
use clap::Args;
#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    #[arg(long)]
    pub json: bool,
}
pub async fn run(args: StatusArgs, global: &crate::Cli) -> Result<(), CliError> {
    let status = serde_json::json!({"runtime":"not-connected", "authenticated_ike":false, "qkd":false, "esp_primitive":"AES-256-GCM-16", "provisioning":"experimental external laboratory provisioning only", "active_sas":null});
    print_output(
        &status,
        if args.json {
            "json"
        } else {
            &global.output_format
        },
        global.verbose,
    );
    Ok(())
}
