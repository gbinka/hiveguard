use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use hiveguard_core::api::{ApiRequest, ApiResponse, ExportFormat};

/// Send an ApiRequest to the daemon socket and receive an ApiResponse.
pub async fn send_request(
    socket_path: &PathBuf,
    request: &ApiRequest,
) -> Result<ApiResponse, String> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("Cannot connect to daemon at {:?}: {}", socket_path, e))?;

    let (reader, mut writer) = stream.into_split();

    let mut json = serde_json::to_string(request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;
    json.push('\n');

    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush: {}", e))?;
    // Shut down write half so server knows we're done sending
    drop(writer);

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if line.is_empty() {
        return Err("Empty response from daemon".to_string());
    }

    serde_json::from_str(line.trim()).map_err(|e| format!("Failed to parse response: {}", e))
}

/// Print an ApiResponse in a human-readable format.
pub fn print_response(response: &ApiResponse) {
    match response {
        ApiResponse::StatusInfo {
            uptime_secs,
            total_bans,
            total_whitelisted,
            version,
        } => {
            println!("HiveGuard v{}", version);
            println!("  Uptime: {}s", format_uptime(*uptime_secs));
            println!("  Active bans: {}", total_bans);
            println!("  Whitelisted: {}", total_whitelisted);
        }
        ApiResponse::Ok { message } => {
            println!("OK: {}", message);
        }
        ApiResponse::Error { message } => {
            eprintln!("Error: {}", message);
        }
        ApiResponse::BanList { bans } => {
            if bans.is_empty() {
                println!("No active bans.");
            } else {
                println!("{:<22} {:<8} {:<24} REASON", "SUBJECT", "SEV", "EXPIRES");
                for ban in bans {
                    let expires = ban
                        .expires_at
                        .as_deref()
                        .unwrap_or("permanent");
                    println!(
                        "{:<22} {:<8} {:<24} {}",
                        ban.subject, ban.severity, expires, ban.reason
                    );
                }
                println!("\nTotal: {} ban(s)", bans.len());
            }
        }
        ApiResponse::WhitelistEntries { entries } => {
            if entries.is_empty() {
                println!("Whitelist is empty.");
            } else {
                println!("Whitelisted networks:");
                for entry in entries {
                    println!("  {}", entry);
                }
                println!("\nTotal: {} entries", entries.len());
            }
        }
        ApiResponse::ThreatList { threats } => {
            if threats.is_empty() {
                println!("No threats recorded.");
            } else {
                println!("{:<22} {:<10} {:<6} LAST SEEN", "IP", "SEVERITY", "BANS");
                for t in threats {
                    println!(
                        "{:<22} {:<10} {:<6} {}",
                        t.ip, t.total_severity, t.ban_count, t.last_seen
                    );
                }
            }
        }
        ApiResponse::ExportData { data, format } => {
            match format {
                ExportFormat::Json => {
                    println!("{}", data);
                }
                ExportFormat::Csv => {
                    print!("{}", data);
                }
            }
        }
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}
