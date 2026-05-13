//! Client-side log collection: a `tracing-subscriber` layer that buffers
//! structured log records for shipment to iroh-services, plus a reload handle
//! that lets the cloud control the level filter at runtime.
//!
//! # The cloud is the source of truth
//!
//! The level filter starts at `off`. No tracing events are captured until the
//! cloud pushes a [`crate::protocol::SetLogLevel`] over the [`ClientHost`]
//! channel. The cloud sends one immediately after authenticating a connected
//! endpoint, derived from the per-endpoint
//! `endpoint_log_settings` row (when present) plus the project default.
//!
//! Concretely this means the install argument is empty: the client process
//! does not get to choose its own log level. The level you see is whatever
//! the dashboard or REST API has decided.
//!
//! [`ClientHost`]: crate::ClientHost
//!
//! # Typical usage
//!
//! ```no_run
//! use iroh_services::logs;
//!
//! # async fn run() -> anyhow::Result<()> {
//! // Buffer-only subscriber, filter starts at `off`.
//! let collector = logs::install()?;
//!
//! // Compose with a stderr fmt layer via `logs::layer()` to also render
//! // filtered events locally:
//! //
//! //     use tracing_subscriber::prelude::*;
//! //     let (collector, log_layer) = iroh_services::logs::layer();
//! //     tracing_subscriber::registry()
//! //         .with(log_layer)
//! //         .with(tracing_subscriber::fmt::layer())
//! //         .init();
//!
//! // Hand the collector to the client builder so it pushes batches over RPC,
//! // and to the ClientHost so the cloud can override the level dynamically.
//! # Ok(())
//! # }
//! ```
//!
//! Backed by a bounded VecDeque of [`LogLine`]; the oldest entries are dropped
//! when the buffer fills, with the drop count reported on the next batch.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use n0_future::{
    task::{AbortOnDropHandle, JoinHandle},
    time::Duration,
};
use tracing::{Event, Subscriber, debug, warn};
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    fmt::{
        format::Writer,
        time::{FormatTime, SystemTime},
    },
    layer::{Context, SubscriberExt as _},
    registry::LookupSpan,
    reload,
    util::SubscriberInitExt as _,
};

use crate::protocol::{FieldValue, LogLine, SpanInfo};

/// Maximum number of buffered log lines awaiting cloud shipment.
///
/// When the buffer is full, the oldest line is dropped to make room and the
/// drop counter is incremented. KISS default; tune from real usage.
pub const DEFAULT_BUFFER_CAPACITY: usize = 1000;

/// Maximum log emission rate per second per process.
///
/// Lines beyond this rate are dropped (counted in the drop counter). The
/// default rate is generous enough to capture useful debug-level traffic
/// without unbounded growth from a runaway log loop.
pub const DEFAULT_RATE_PER_SECOND: u32 = 100;

/// Errors that can occur while installing the log collector.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The default tracing dispatcher is already set; install once at startup.
    #[error("global tracing dispatcher is already set")]
    AlreadyInstalled,
    /// The supplied directives string was rejected by `EnvFilter`.
    #[error("invalid filter directives: {0}")]
    InvalidDirectives(String),
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

/// Handle to the buffered log collector. Cheap to clone; all clones share the
/// same backing buffer and reload handle.
#[derive(Clone)]
pub struct LogCollector {
    inner: Arc<CollectorInner>,
}

struct CollectorInner {
    buffer: Mutex<RingBuffer>,
    reload_handle: reload::Handle<EnvFilter, Registry>,
    revert_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

/// Off-state directive. The buffer captures nothing until the cloud sends
/// a `SetLogLevel` with something more permissive.
const OFF_DIRECTIVES: &str = "off";

struct RingBuffer {
    lines: VecDeque<LogLine>,
    dropped: u32,
    capacity: usize,
    rate_per_second: u32,
    window_start: Instant,
    window_count: u32,
}

impl RingBuffer {
    fn new(capacity: usize, rate_per_second: u32) -> Self {
        Self {
            lines: VecDeque::with_capacity(capacity.min(64)),
            dropped: 0,
            capacity,
            rate_per_second,
            window_start: Instant::now(),
            window_count: 0,
        }
    }

    fn push(&mut self, line: LogLine) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.window_count = 0;
        }
        if self.window_count >= self.rate_per_second {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.window_count += 1;

        if self.lines.len() == self.capacity {
            self.lines.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.lines.push_back(line);
    }

    fn drain(&mut self, max: usize) -> (Vec<LogLine>, u32) {
        let take = self.lines.len().min(max);
        let lines: Vec<LogLine> = self.lines.drain(..take).collect();
        let dropped = std::mem::take(&mut self.dropped);
        (lines, dropped)
    }
}

impl LogCollector {
    /// Returns the current number of buffered lines.
    pub fn buffered(&self) -> usize {
        self.inner.buffer.lock().expect("poisoned").lines.len()
    }

    /// Drains up to `max` lines from the buffer, along with the count of lines
    /// dropped since the last drain.
    pub fn drain(&self, max: usize) -> (Vec<LogLine>, u32) {
        self.inner.buffer.lock().expect("poisoned").drain(max)
    }

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
}

impl std::fmt::Debug for LogCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogCollector")
            .field("buffered", &self.buffered())
            .finish()
    }
}

/// Installs a global tracing subscriber whose only output is a JSON-buffering
/// layer that ships records to the cloud. The level filter starts at `off`;
/// the cloud must push a `SetLogLevel` for any events to be captured.
///
/// Call exactly once at process start. For local console output in addition
/// to cloud shipping, use [`layer`] and compose your own subscriber.
pub fn install() -> Result<LogCollector, InstallError> {
    let (collector, layer) = layer();
    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .map_err(|_| InstallError::AlreadyInstalled)?;
    debug!("iroh-services log collector installed");
    Ok(collector)
}

/// Builds the buffer layer and its [`LogCollector`] handle without installing
/// a global subscriber. Use this when composing the collector with other
/// layers; it returns the layer pre-wrapped in the reloadable filter.
///
/// Typical pattern for buffer + stderr fmt:
///
/// ```no_run
/// use iroh_services::logs;
/// use tracing_subscriber::prelude::*;
///
/// let (collector, log_layer) = logs::layer();
/// tracing_subscriber::registry()
///     .with(log_layer)
///     .with(tracing_subscriber::fmt::layer())
///     .try_init()
///     .ok();
/// # let _ = collector;
/// ```
pub fn layer() -> (LogCollector, impl Layer<Registry> + Send + Sync + 'static) {
    // `EnvFilter::try_new("off")` cannot fail; "off" is always valid.
    let filter = EnvFilter::try_new(OFF_DIRECTIVES).expect("'off' is always a valid directive");
    let (filter, reload_handle) = reload::Layer::new(filter);

    let inner = Arc::new(CollectorInner {
        buffer: Mutex::new(RingBuffer::new(
            DEFAULT_BUFFER_CAPACITY,
            DEFAULT_RATE_PER_SECOND,
        )),
        reload_handle,
        revert_task: Mutex::new(None),
    });
    let collector = LogCollector {
        inner: inner.clone(),
    };
    let buffer_layer = BufferLayer { inner };
    (collector, buffer_layer.with_filter(filter))
}

struct BufferLayer {
    inner: Arc<CollectorInner>,
}

impl<S> Layer<S> for BufferLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut timestamp = String::new();
        let _ = SystemTime.format_time(&mut Writer::new(&mut timestamp));

        let mut field_visitor = FieldVisitor::default();
        event.record(&mut field_visitor);

        let mut spans: Vec<SpanInfo> = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                spans.push(SpanInfo {
                    name: span.name().to_string(),
                    fields: Vec::new(),
                });
            }
        }

        let line = LogLine {
            timestamp,
            level: metadata.level().to_string(),
            target: metadata.target().to_string(),
            fields: field_visitor.fields,
            spans,
        };

        self.inner.buffer.lock().expect("poisoned").push(line);
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: Vec<(String, FieldValue)>,
}

impl FieldVisitor {
    fn push(&mut self, field: &tracing::field::Field, value: FieldValue) {
        self.fields.push((field.name().to_string(), value));
    }
}

impl tracing::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field, FieldValue::Str(value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push(field, FieldValue::I64(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push(field, FieldValue::U64(value));
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.push(field, FieldValue::Other(value.to_string()));
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.push(field, FieldValue::Other(value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push(field, FieldValue::Bool(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.push(field, FieldValue::F64(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // The implicit `message` field arrives here when the producer used a
        // bare format string (`info!("hello {x}")`). Store it as a plain
        // string so the dashboard does not show it wrapped in quotes from a
        // generic `Debug` formatter.
        if field.name() == "message" {
            self.push(field, FieldValue::Str(format!("{value:?}")));
        } else {
            self.push(field, FieldValue::Other(format!("{value:?}")));
        }
    }
}

/// How often the rolling file appender starts a new file.
///
/// Re-exported from `tracing-appender` so callers don't need to depend on it
/// directly.
pub use tracing_appender::rolling::Rotation;

/// Guard returned by [`file_layer`] that keeps the non-blocking writer's
/// worker thread alive. Drop this only at process shutdown; once dropped,
/// any buffered records still in flight are flushed and the file layer
/// stops accepting writes.
pub use tracing_appender::non_blocking::WorkerGuard;

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

/// Builds a tracing layer that writes records to a rolling file under
/// `config.dir`. Returns the layer plus a [`WorkerGuard`] the caller must
/// hold for the lifetime of the process — drop it at shutdown so any
/// buffered records flush before exit.
///
/// The layer is not filtered. Compose it with the rest of your subscriber
/// to control what reaches the file. A common pattern is to use the same
/// [`EnvFilter`] reload handle as the cloud-controlled buffer layer, so a
/// dashboard-pushed `SetLogLevel` adjusts file output too.
///
/// # Example
///
/// ```no_run
/// use iroh_services::logs::{FileLoggerConfig, Rotation};
/// use tracing_subscriber::prelude::*;
///
/// # fn main() -> anyhow::Result<()> {
/// let (file_layer, _guard) = iroh_services::logs::file_layer(
///     FileLoggerConfig::new("./logs")
///         .with_rotation(Rotation::HOURLY)
///         .with_max_files(Some(24)),
/// )?;
///
/// tracing_subscriber::registry()
///     .with(file_layer)
///     .init();
/// # // Keep `_guard` alive for the program lifetime.
/// # Ok(())
/// # }
/// ```
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

    fn message_is(line: &LogLine, want: &str) -> bool {
        line.fields
            .iter()
            .any(|(k, v)| k == "message" && matches!(v, FieldValue::Str(s) if s == want))
    }

    #[test]
    fn ring_buffer_rolls_over_oldest() {
        let mut buf = RingBuffer::new(2, 1000);
        for i in 0..5 {
            buf.push(LogLine {
                timestamp: format!("{i}"),
                level: "INFO".into(),
                target: "test".into(),
                fields: Vec::new(),
                spans: Vec::new(),
            });
        }
        let (lines, dropped) = buf.drain(10);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].timestamp, "3");
        assert_eq!(lines[1].timestamp, "4");
        assert_eq!(dropped, 3);
    }

    #[test]
    fn ring_buffer_throttles_per_second() {
        let mut buf = RingBuffer::new(1000, 2);
        for i in 0..10 {
            buf.push(LogLine {
                timestamp: format!("{i}"),
                level: "INFO".into(),
                target: "test".into(),
                fields: Vec::new(),
                spans: Vec::new(),
            });
        }
        let (lines, dropped) = buf.drain(100);
        assert_eq!(lines.len(), 2);
        assert_eq!(dropped, 8);
    }

    #[tokio::test]
    async fn collector_reload_changes_filter_then_reverts() {
        let collector = match install() {
            Ok(c) => c,
            Err(InstallError::AlreadyInstalled) => return,
            Err(e) => panic!("install: {e}"),
        };

        // Filter starts at "off" — even info lines are dropped.
        tracing::info!(target: "logtest", "should not appear yet");
        let (lines, _) = collector.drain(100);
        assert!(!lines.iter().any(|l| message_is(l, "should not appear yet")));

        // Cloud raises the level to info.
        collector.set_filter("info", None, None).unwrap();
        tracing::info!(target: "logtest", "first info");
        tracing::trace!(target: "logtest", "should not appear");
        let (lines, _) = collector.drain(100);
        assert!(
            lines
                .iter()
                .any(|l| l.target == "logtest" && message_is(l, "first info"))
        );
        assert!(!lines.iter().any(|l| message_is(l, "should not appear")));

        // Cloud raises again to trace, with TTL and a revert target.
        collector
            .set_filter("trace", Some(Duration::from_millis(150)), Some("info"))
            .unwrap();
        tracing::trace!(target: "logtest", "should appear");
        let (lines, _) = collector.drain(100);
        assert!(lines.iter().any(|l| message_is(l, "should appear")));

        n0_future::time::sleep(Duration::from_millis(300)).await;
        tracing::trace!(target: "logtest", "should not appear after revert");
        let (lines, _) = collector.drain(100);
        assert!(
            !lines
                .iter()
                .any(|l| message_is(l, "should not appear after revert"))
        );
    }

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
        // Drop the guard so the non-blocking writer flushes its queue.
        drop(guard);

        // Find a file produced by the rolling appender and confirm our line
        // is in it.
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
}
