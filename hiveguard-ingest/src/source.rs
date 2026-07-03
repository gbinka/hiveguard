use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;

type Result<T> = std::result::Result<T, HiveGuardError>;

/// Trait for log sources that produce normalized events.
#[async_trait::async_trait]
pub trait LogSource: Send + Sync {
    fn name(&self) -> &str;
    async fn start(&mut self, sender: tokio::sync::mpsc::Sender<NormalizedEvent>) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
}
