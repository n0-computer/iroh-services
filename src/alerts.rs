use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;

use crate::protocol::{AlertInfo, LogEntry};

const CONTEXT_BUFFER_SIZE: usize = 200;

/// A [`tracing_subscriber::Layer`] that captures ERROR-level log events from
/// the `iroh` crate and forwards them to the n0des cloud via the client actor.
///
/// All log events (any level, any target) are recorded into a 200-entry ring
/// buffer. When an ERROR from the `iroh` crate fires, the buffered context is
/// drained and sent alongside the alert.
///
/// Returned by [`Client::enable_alerts`]. The caller must install this layer
/// into their tracing subscriber stack for alerts to fire.
///
/// [`Client::enable_alerts`]: crate::Client::enable_alerts
#[derive(Debug)]
pub struct LogMonitor {
    tx: mpsc::Sender<AlertInfo>,
    context_buffer: Mutex<VecDeque<LogEntry>>,
}

impl LogMonitor {
    pub(crate) fn new(tx: mpsc::Sender<AlertInfo>) -> Self {
        Self {
            tx,
            context_buffer: Mutex::new(VecDeque::with_capacity(CONTEXT_BUFFER_SIZE)),
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for LogMonitor {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let level = *meta.level();

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = visitor.message.unwrap_or_default();

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Record every event into the ring buffer for context.
        let entry = LogEntry {
            level: level.to_string(),
            target: meta.target().to_string(),
            message: message.clone(),
            timestamp_ms,
        };

        let mut buf = self
            .context_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if buf.len() >= CONTEXT_BUFFER_SIZE {
            buf.pop_front();
        }
        buf.push_back(entry);

        // Only fire an alert for ERROR-level events from iroh targets.
        if level != tracing::Level::ERROR || !meta.target().starts_with("iroh") {
            return;
        }

        let context: Vec<LogEntry> = buf.drain(..).collect();

        let alert = AlertInfo {
            target: meta.target().to_string(),
            message,
            file: meta.file().map(String::from),
            line: meta.line(),
            timestamp_ms,
            iroh_version: crate::IROH_VERSION.to_string(),
            iroh_n0des_version: crate::IROH_N0DES_VERSION.to_string(),
            context,
        };

        // Non-blocking send. If the channel is full the alert is dropped —
        // alerting is best-effort and must never block the caller's thread.
        let _ = self.tx.try_send(alert);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}
