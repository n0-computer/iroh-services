//! Client-side log collection: a `tracing-subscriber` layer that writes
//! structured log records to rolling files on the local filesystem, plus a
//! reload handle that lets the cloud control the level filter at runtime.
//!
//! # The cloud is the source of truth for the level
//!
//! The level filter starts at `off`. No tracing events are captured until the
//! cloud pushes a [`crate::protocol::SetLogLevel`] over the [`ClientHost`]
//! channel. The cloud sends one immediately after authenticating a connected
//! endpoint, derived from the per-endpoint `endpoint_log_settings` row (when
//! present) plus the project default.
//!
//! [`ClientHost`]: crate::ClientHost
//!
//! # Files live on the device
//!
//! Records land in rolling JSON files under a caller-supplied directory.
//! Operators view, ship, or aggregate them with whatever tooling they
//! already use (`tail`, `journalctl`, `vector`, etc.).
//!
//! # Typical usage
//!
//! ```no_run
//! use iroh_services::logs::{self, FileLoggerConfig};
//!
//! # fn main() -> anyhow::Result<()> {
//! // Installs a global subscriber. The filter starts at `off`; the
//! // Client pulls the cloud-persisted directive right after Auth and
//! // applies it via the collector. The dashboard can also push live
//! // overrides via ClientHost::set_log_level after that.
//! let (collector, _guard) = logs::install(FileLoggerConfig::new("./logs"))?;
//! # let _ = collector;
//! # Ok(())
//! # }
//! ```
//!
//! Compose with additional layers (for example, a stderr fmt layer) via
//! [`layer`]:
//!
//! ```no_run
//! use iroh_services::logs::{self, FileLoggerConfig};
//! use tracing_subscriber::prelude::*;
//!
//! # fn main() -> anyhow::Result<()> {
//! let (collector, file_layer, _guard) = logs::layer(FileLoggerConfig::new("./logs"))?;
//! tracing_subscriber::registry()
//!     .with(file_layer)
//!     .with(tracing_subscriber::fmt::layer())
//!     .try_init()
//!     .ok();
//! # let _ = collector;
//! # Ok(())
//! # }
//! ```

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use n0_future::{
    task::{AbortOnDropHandle, JoinHandle},
    time::Duration,
};
use tracing::{Subscriber, debug, warn};
use tracing_subscriber::{
    EnvFilter, Layer, Registry, layer::SubscriberExt as _, registry::LookupSpan, reload,
    util::SubscriberInitExt as _,
};

/// Errors that can occur while installing the log collector.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The default tracing dispatcher is already set; install once at startup.
    #[error("global tracing dispatcher is already set")]
    AlreadyInstalled,
    /// File logger setup failed (could not create directory, open appender,
    /// etc.).
    #[error("file logger setup failed: {0}")]
    FileLogger(#[from] FileLoggerError),
}

/// Errors that can occur while changing the active filter at runtime.
#[derive(Debug, thiserror::Error)]
pub enum SetFilterError {
    /// The supplied directives string was rejected by `EnvFilter`.
    #[error("invalid filter directives: {0}")]
    InvalidDirectives(String),
    /// Reloading the filter failed because the subscriber went away.
    #[error("reload handle is no longer valid")]
    ReloadFailed,
}

/// Handle to the cloud-controlled tracing filter. Cheap to clone; all clones
/// share the same backing reload handle.
#[derive(Clone)]
pub struct LogCollector {
    inner: Arc<CollectorInner>,
}

struct CollectorInner {
    reload_handle: reload::Handle<EnvFilter, Registry>,
    revert_task: Mutex<Option<AbortOnDropHandle<()>>>,
    /// Directory where the rolling file appender writes. Used by
    /// [`LogCollector::serve_fetch_logs`] to locate the current file.
    log_dir: PathBuf,
    /// Filename prefix the rolling appender uses; the date suffix is
    /// appended for each rolled-over file.
    file_name_prefix: String,
}

/// Off-state directive. Nothing is captured until the cloud sends a
/// `SetLogLevel` with something more permissive.
const OFF_DIRECTIVES: &str = "off";

impl LogCollector {
    /// Sets the active filter directives. When `expires_in` is set,
    /// schedules a revert after that duration. The revert target is
    /// `revert_to` when supplied; `None` means revert to `off`.
    pub fn set_filter(
        &self,
        directives: &str,
        expires_in: Option<Duration>,
        revert_to: Option<&str>,
    ) -> Result<(), SetFilterError> {
        let filter = EnvFilter::try_new(directives)
            .map_err(|e| SetFilterError::InvalidDirectives(e.to_string()))?;
        self.inner
            .reload_handle
            .reload(filter)
            .map_err(|_| SetFilterError::ReloadFailed)?;

        let mut guard = self.inner.revert_task.lock().expect("poisoned");
        *guard = None;

        if let Some(expires_in) = expires_in {
            let collector = self.clone();
            let revert_to = revert_to.map(str::to_string);
            let handle: JoinHandle<()> = n0_future::task::spawn(async move {
                n0_future::time::sleep(expires_in).await;
                let target = revert_to.as_deref();
                if let Err(err) = collector.revert(target) {
                    warn!(?err, "failed to revert log filter");
                }
            });
            *guard = Some(AbortOnDropHandle::new(handle));
        }
        Ok(())
    }

    /// Reverts the active filter to `to`, or to the off state when `to` is
    /// `None`.
    pub fn revert(&self, to: Option<&str>) -> Result<(), SetFilterError> {
        let directives = to.unwrap_or(OFF_DIRECTIVES);
        let filter = EnvFilter::try_new(directives)
            .map_err(|e| SetFilterError::InvalidDirectives(e.to_string()))?;
        self.inner
            .reload_handle
            .reload(filter)
            .map_err(|_| SetFilterError::ReloadFailed)
    }

    /// Locate the newest rolling file in the configured log directory
    /// whose name starts with the configured filename prefix. Returns
    /// `Ok(None)` when the directory exists but no matching file is
    /// present. Used by [`crate::ClientHost`] to serve [`FetchLogs`].
    ///
    /// [`FetchLogs`]: crate::protocol::FetchLogs
    pub(crate) fn current_log_file(&self) -> std::io::Result<Option<PathBuf>> {
        let dir = &self.inner.log_dir;
        let prefix = &self.inner.file_name_prefix;
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(prefix) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            match &best {
                Some((_, current)) if *current >= mtime => {}
                _ => best = Some((entry.path(), mtime)),
            }
        }
        Ok(best.map(|(p, _)| p))
    }
}

impl std::fmt::Debug for LogCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogCollector").finish_non_exhaustive()
    }
}

/// Installs a global tracing subscriber whose only output is a rolling
/// file appender under `config.dir`. The level filter starts at `off`; the
/// cloud must push a `SetLogLevel` for any events to be captured.
///
/// Returns the [`LogCollector`] to hand to [`crate::ClientHost`] so it can
/// apply runtime overrides, and a [`WorkerGuard`] the caller must hold for
/// the lifetime of the process so the non-blocking writer flushes on exit.
///
/// Call exactly once at process start. For composition with other layers,
/// use [`layer`].
pub fn install(config: FileLoggerConfig) -> Result<(LogCollector, WorkerGuard), InstallError> {
    let (collector, file_layer, guard) = layer(config)?;
    tracing_subscriber::registry()
        .with(file_layer)
        .try_init()
        .map_err(|_| InstallError::AlreadyInstalled)?;
    debug!("iroh-services file logger installed");
    Ok((collector, guard))
}

/// Builds the cloud-controlled file layer and its [`LogCollector`] without
/// installing a global subscriber. Use this when composing the file layer
/// with other layers; the returned layer is pre-wrapped in the reloadable
/// filter so the cloud's `SetLogLevel` overrides take effect.
pub fn layer(
    config: FileLoggerConfig,
) -> Result<
    (
        LogCollector,
        impl Layer<Registry> + Send + Sync + 'static,
        WorkerGuard,
    ),
    InstallError,
> {
    // `EnvFilter::try_new("off")` cannot fail; "off" is always valid.
    let filter = EnvFilter::try_new(OFF_DIRECTIVES).expect("'off' is always a valid directive");
    let (filter, reload_handle) = reload::Layer::new(filter);

    let log_dir = config.dir.clone();
    let file_name_prefix = config.file_name_prefix.clone();
    let (file_layer, guard) = file_layer::<Registry>(config)?;
    let layer = file_layer.with_filter(filter);

    let inner = Arc::new(CollectorInner {
        reload_handle,
        revert_task: Mutex::new(None),
        log_dir,
        file_name_prefix,
    });
    let collector = LogCollector { inner };
    Ok((collector, layer, guard))
}

/// Guard returned by [`file_layer`] / [`layer`] / [`install`] that keeps the
/// non-blocking writer's worker thread alive. Drop this only at process
/// shutdown; once dropped, any buffered records still in flight are flushed
/// and the file layer stops accepting writes.
pub use tracing_appender::non_blocking::WorkerGuard;
/// How often the rolling file appender starts a new file.
///
/// Re-exported from `tracing-appender` so callers don't need to depend on it
/// directly.
pub use tracing_appender::rolling::Rotation;

/// Errors raised when constructing the file logger.
#[derive(Debug, thiserror::Error)]
pub enum FileLoggerError {
    /// Could not create the log directory or open the rolling appender.
    #[error("file logger setup failed: {0}")]
    Io(#[from] std::io::Error),
    /// `tracing-appender`'s builder rejected the configuration (for example
    /// an invalid filename prefix).
    #[error("file logger builder rejected configuration: {0}")]
    Builder(String),
}

/// Configuration for the rolling file logger.
///
/// Use [`FileLoggerConfig::new`] to set the destination directory and tune
/// the remaining fields with the with-style setters. The defaults are
/// daily rotation, a `iroh-services` filename prefix, and a 30-file
/// retention window.
#[derive(Debug, Clone)]
pub struct FileLoggerConfig {
    dir: PathBuf,
    rotation: Rotation,
    file_name_prefix: String,
    max_files: Option<usize>,
}

impl FileLoggerConfig {
    /// Build a config rooted at `dir`. The directory is created on first
    /// write if it does not exist.
    pub fn new<P: Into<PathBuf>>(dir: P) -> Self {
        Self {
            dir: dir.into(),
            rotation: Rotation::DAILY,
            file_name_prefix: "iroh-services".into(),
            max_files: Some(30),
        }
    }

    /// Override the rotation cadence. Default: [`Rotation::DAILY`].
    pub fn with_rotation(mut self, rotation: Rotation) -> Self {
        self.rotation = rotation;
        self
    }

    /// Override the file name stem. Rotation appends a date suffix to this.
    /// Default: `iroh-services`.
    pub fn with_file_name_prefix<S: Into<String>>(mut self, prefix: S) -> Self {
        self.file_name_prefix = prefix.into();
        self
    }

    /// Override the retention cap. `None` keeps every file forever; `Some(n)`
    /// keeps at most `n` files and deletes the oldest on rotation. Default:
    /// `Some(30)`.
    pub fn with_max_files(mut self, max_files: Option<usize>) -> Self {
        self.max_files = max_files;
        self
    }
}

/// Builds an unfiltered tracing layer that writes records to a rolling
/// file under `config.dir`. Returns the layer plus a [`WorkerGuard`] the
/// caller must hold for the lifetime of the process — drop it at shutdown
/// so any buffered records flush before exit.
///
/// Most callers want [`layer`] or [`install`] instead, which apply the
/// cloud-controlled `EnvFilter` reload handle. Use this when you want a
/// plain file appender with no cloud filter integration.
pub fn file_layer<S>(
    config: FileLoggerConfig,
) -> Result<(impl Layer<S> + Send + Sync + 'static, WorkerGuard), FileLoggerError>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let FileLoggerConfig {
        dir,
        rotation,
        file_name_prefix,
        max_files,
    } = config;

    create_dir_all(&dir)?;

    let mut builder = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(file_name_prefix);
    if let Some(max) = max_files {
        builder = builder.max_log_files(max);
    }
    let appender = builder
        .build(&dir)
        .map_err(|e| FileLoggerError::Builder(e.to_string()))?;

    let (writer, guard) = tracing_appender::non_blocking(appender);
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .json();
    Ok((layer, guard))
}

fn create_dir_all(dir: &Path) -> Result<(), FileLoggerError> {
    std::fs::create_dir_all(dir).map_err(FileLoggerError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `file_layer` writes records to a file in the configured directory,
    /// and the WorkerGuard flushes pending writes on drop.
    #[test]
    fn file_layer_writes_to_disk() {
        use tracing::Dispatch;
        use tracing_subscriber::{Registry, layer::SubscriberExt};

        let tmp = tempfile::tempdir().unwrap();
        let (layer, guard) = file_layer::<Registry>(
            FileLoggerConfig::new(tmp.path())
                .with_file_name_prefix("test")
                .with_max_files(Some(2)),
        )
        .expect("file_layer setup");

        let subscriber = Registry::default().with(layer);
        let dispatch = Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "file_layer_test", "hello from the file logger");
        });
        drop(guard);

        let mut found = false;
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_name().to_string_lossy().starts_with("test") {
                continue;
            }
            let contents = std::fs::read_to_string(entry.path()).unwrap();
            if contents.contains("hello from the file logger") {
                found = true;
                break;
            }
        }
        assert!(found, "expected log line to be written to a test.* file");
    }

    /// The cloud-controlled `layer` starts captured-nothing and only writes
    /// after `set_filter` raises the level. Verifies the reload handle is
    /// wired to the file layer end-to-end.
    #[tokio::test(flavor = "current_thread")]
    async fn cloud_filter_controls_file_writes() {
        use tracing::Dispatch;

        let tmp = tempfile::tempdir().unwrap();
        let (collector, log_layer, guard) =
            layer(FileLoggerConfig::new(tmp.path()).with_file_name_prefix("controlled")).unwrap();

        let subscriber = Registry::default().with(log_layer);
        let dispatch = Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            // Captured nothing yet — filter is "off".
            tracing::info!(target: "logtest", "before-set");

            collector
                .set_filter("info", None, None)
                .expect("set_filter to info");
            tracing::info!(target: "logtest", "after-set");
        });
        drop(guard);

        let mut combined = String::new();
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("controlled")
            {
                combined.push_str(&std::fs::read_to_string(entry.path()).unwrap());
            }
        }
        assert!(
            !combined.contains("before-set"),
            "before-set should be filtered out, got: {combined}"
        );
        assert!(
            combined.contains("after-set"),
            "after-set should be written after set_filter, got: {combined}"
        );
    }
}
