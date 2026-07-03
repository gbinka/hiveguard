use std::pin::Pin;

use crate::context::PluginContext;
use crate::error::PluginResult;
use crate::manifest::{PluginKind, PluginManifest};
use crate::traits::{
    cti_provider::CtiProviderPlugin, detector::DetectorPlugin, enforcer::EnforcerPlugin,
    log_source::LogSourcePlugin, notifier::NotifierPlugin, scoring_engine::ScoringEnginePlugin,
    siem_sink::SiemSinkPlugin, ui_server::UiServerPlugin,
};

/// Bump this on **breaking** changes to any plugin trait or descriptor field.
/// The host refuses to load plugins built against a different `API_VERSION`.
pub const API_VERSION: u32 = 1;

/// Boxed future returned by every plugin factory.
pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Per-kind factory. Each variant carries an `fn` pointer that returns a
/// trait object of the appropriate type after `init` has been run.
///
/// We keep this as an enum (rather than a single erased factory) so that the
/// host gets a compile-time guarantee that a `notifier.*` descriptor produces
/// a `NotifierPlugin` and never a `LogSourcePlugin`.
pub enum PluginFactory {
    LogSource(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>>,
    ),
    Notifier(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn NotifierPlugin>>>,
    ),
    Enforcer(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn EnforcerPlugin>>>,
    ),
    CtiProvider(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn CtiProviderPlugin>>>,
    ),
    SiemSink(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn SiemSinkPlugin>>>,
    ),
    Detector(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>>,
    ),
    ScoringEngine(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn ScoringEnginePlugin>>>,
    ),
    UiServer(
        fn(
            ctx: PluginContext,
            cfg: serde_json::Value,
        ) -> BoxFuture<'static, PluginResult<Box<dyn UiServerPlugin>>>,
    ),
}

impl PluginFactory {
    /// Expected category for this factory variant — used by the host to
    /// sanity-check that `kind` and `factory` agree.
    pub fn kind(&self) -> PluginKind {
        match self {
            PluginFactory::LogSource(_) => PluginKind::LogSource,
            PluginFactory::Notifier(_) => PluginKind::Notifier,
            PluginFactory::Enforcer(_) => PluginKind::Enforcer,
            PluginFactory::CtiProvider(_) => PluginKind::CtiProvider,
            PluginFactory::SiemSink(_) => PluginKind::SiemSink,
            PluginFactory::Detector(_) => PluginKind::Detector,
            PluginFactory::ScoringEngine(_) => PluginKind::ScoringEngine,
            PluginFactory::UiServer(_) => PluginKind::UiServer,
        }
    }
}

/// Static descriptor submitted by every plugin crate via `inventory::submit!`.
///
/// The host iterates `inventory::iter::<PluginDescriptor>` at startup,
/// matches each entry against the user's `plugins:` section in YAML, validates
/// the config against `config_schema`, and finally invokes `factory`.
pub struct PluginDescriptor {
    pub id: &'static str,
    pub kind: PluginKind,
    pub api_version: u32,
    pub manifest: fn() -> PluginManifest,
    pub config_schema: &'static str,
    pub factory: PluginFactory,
}

inventory::collect!(PluginDescriptor);

/// Iterate all plugins linked into the current binary. Order is undefined.
pub fn iter_descriptors() -> impl Iterator<Item = &'static PluginDescriptor> {
    inventory::iter::<PluginDescriptor>.into_iter()
}

/// Look up a single plugin descriptor by id. `None` if not linked in.
pub fn find_descriptor(id: &str) -> Option<&'static PluginDescriptor> {
    iter_descriptors().find(|d| d.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iter_returns_no_descriptors_in_unit_test() {
        // No plugins are linked into the API crate's own test binary —
        // this just exercises the public surface.
        let count = iter_descriptors().count();
        assert_eq!(count, 0);
    }
}
