use crate::def::LogLevel;
use anyhow::anyhow;
#[cfg(feature = "telemetry")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::{Protocol, WithExportConfig};
#[cfg(feature = "telemetry")]
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
};
use serde::Serialize;
use std::{io::IsTerminal, sync::Once};
use tokio::sync::broadcast::Sender;
use tracing::level_filters::LevelFilter;
use tracing_log::LogTracer;
#[cfg(feature = "telemetry")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(target_os = "ios")]
use tracing_oslog::OsLogger;
use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, fmt::time::LocalTime, prelude::*,
};

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Silent => LevelFilter::OFF,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: LogLevel,
    #[serde(rename = "payload")]
    pub msg: String,
}

pub struct EventCollector(Vec<Sender<LogEvent>>);

impl EventCollector {
    pub fn new(receivers: Vec<Sender<LogEvent>>) -> Self {
        Self(receivers)
    }
}

impl<S> Layer<S> for EventCollector
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut strs = vec![];
        event.record(&mut EventVisitor(&mut strs));

        let event = LogEvent {
            level: match *event.metadata().level() {
                tracing::Level::ERROR => LogLevel::Error,
                tracing::Level::WARN => LogLevel::Warning,
                tracing::Level::INFO => LogLevel::Info,
                tracing::Level::DEBUG => LogLevel::Debug,
                tracing::Level::TRACE => LogLevel::Trace,
            },
            msg: strs.join(" "),
        };
        for tx in &self.0 {
            _ = tx.send(event.clone());
        }
    }
}

struct LoggingGuard {
    _file_appender: Option<tracing_appender::non_blocking::WorkerGuard>,
    #[cfg(feature = "telemetry")]
    _tracing_chrome: Option<tracing_chrome::FlushGuard>,
    #[cfg(feature = "telemetry")]
    _tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

static SETUP_LOGGING: Once = Once::new();
static mut LOGGING_GUARD: Option<LoggingGuard> = None;

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) {
    unsafe {
        SETUP_LOGGING.call_once(|| {
            LogTracer::init().unwrap_or_else(|e| {
                eprintln!(
                    "Failed to init tracing-log: {e}, another env_logger might \
                     have been initialized"
                );
            });
            LOGGING_GUARD = setup_logging_inner(level, collector, cwd, log_file)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to setup logging: {e}");
                    None
                });
        });
    }
}

fn setup_logging_inner(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<Option<LoggingGuard>> {
    let default_log_level = format!("warn,clash={level}");
    let filter = EnvFilter::try_from_default_env()
        .inspect(|f| {
            eprintln!("using env log level: {f}");
        })
        .inspect_err(|_| {
            if let Ok(log_level) = std::env::var("RUST_LOG") {
                eprintln!("Failed to parse log level from environment: {log_level}");
                eprintln!("Using default log level: {default_log_level}");
            }
        })
        .unwrap_or(EnvFilter::new(default_log_level));

    let (appender, guard) = if let Some(log_file) = log_file {
        let path_buf = std::path::PathBuf::from(&log_file);
        let log_path = if path_buf.is_absolute() {
            log_file
        } else {
            format!("{cwd}/{log_file}")
        };
        let writer = std::fs::File::options().append(true).open(log_path)?;
        let (non_blocking, guard) =
            tracing_appender::non_blocking::NonBlockingBuilder::default()
                .buffered_lines_limit(16_000)
                .lossy(true)
                .thread_name("clash-logger-appender")
                .finish(writer);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    #[cfg(feature = "telemetry")]
    let (tracing_chrome, tracing_chrome_g) = if cfg!(feature = "telemetry") {
        let builder = tracing_chrome::ChromeLayerBuilder::new();
        let (layer, guard) = builder.build();
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    #[cfg(feature = "telemetry")]
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()
        .unwrap();

    #[cfg(feature = "telemetry")]
    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // Customize sampling strategy
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
            opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
                if cfg!(debug_assertions) {
                    1.0 // 100% sampling in development
                } else {
                    0.1 // 10% sampling in production
                },
            ),
        )))
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(env!("CARGO_PKG_NAME"))
                .with_schema_url(
                    [
                        opentelemetry::KeyValue::new(
                            SERVICE_VERSION,
                            env!("CARGO_PKG_VERSION"),
                        ),
                        opentelemetry::KeyValue::new(
                            DEPLOYMENT_ENVIRONMENT_NAME,
                            if cfg!(debug_assertions) {
                                "development"
                            } else {
                                "production"
                            },
                        ),
                    ],
                    SCHEMA_URL,
                )
                .build(),
        )
        .with_batch_exporter(exporter)
        .build();
    #[cfg(feature = "telemetry")]
    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    let subscriber = tracing_subscriber::registry();

    // Collect and expose data about the Tokio runtime (tasks, threads,
    // resources, etc.) — gated on tokio_unstable because console_subscriber
    // panics at runtime if Tokio was compiled without --cfg tokio_unstable.
    // When tests are run with RUSTFLAGS="--cfg docker_test", that env-var
    // overrides .cargo/config.toml, so tokio_unstable is absent and the
    // gate correctly excludes this code.
    #[cfg(all(feature = "telemetry", tokio_unstable))]
    let subscriber = subscriber.with(console_subscriber::spawn());
    #[cfg(all(feature = "telemetry", tokio_unstable))]
    let filter = filter
        .add_directive("tokio=trace".parse().unwrap())
        .add_directive("runtime=trace".parse().unwrap());
    let exclude = filter_fn(|metadata| {
        !metadata.target().contains("tokio")
            && !metadata.target().contains("runtime")
    });

    let timer = LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]:[subsecond]"
    ));

    let log_to_file_layer = appender.map(|x| {
        tracing_subscriber::fmt::Layer::new()
            .with_timer(timer.clone())
            .with_ansi(false)
            .compact()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_writer(x)
            .with_filter(exclude.clone())
    });
    let log_stdout_layer = tracing_subscriber::fmt::Layer::new()
        .with_timer(timer)
        .with_ansi(std::io::stdout().is_terminal())
        .compact()
        .with_target(cfg!(debug_assertions))
        .with_file(true)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(cfg!(debug_assertions))
        .with_writer(std::io::stdout)
        .with_filter(exclude.clone());

    let subscriber = {
        #[cfg(feature = "telemetry")]
        {
            subscriber
                .with(filter) // Global filter
                .with(tracing_chrome)
                .with(OpenTelemetryLayer::new(tracer))
                .with(collector.with_filter(exclude.clone()))
                .with(log_to_file_layer)
                .with(log_stdout_layer)
        }
        #[cfg(not(feature = "telemetry"))]
        {
            subscriber
                .with(filter) // Global filter
                .with(collector.with_filter(exclude.clone()))
                .with(log_to_file_layer)
                .with(log_stdout_layer)
        }
    };

    #[cfg(target_os = "ios")]
    let subscriber =
        subscriber.with(Some(OsLogger::new("com.watfaq.clash", "default")));

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;

    Ok(Some(LoggingGuard {
        _file_appender: guard,
        #[cfg(feature = "telemetry")]
        _tracing_chrome: tracing_chrome_g,
        #[cfg(feature = "telemetry")]
        _tracer_provider: Some(tracer_provider),
    }))
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl EventVisitor<'_> {
    fn push_display(
        &mut self,
        field: &tracing::field::Field,
        value: impl std::fmt::Display,
    ) {
        if field.name() != "message" {
            self.0.push(format!("{}={}", field.name(), value));
        }
    }

    fn push_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        } else {
            self.0.push(format!("{}={value:?}", field.name()));
        }
    }
}

impl tracing::field::Visit for EventVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.push_display(field, value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push_display(field, value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push_display(field, value);
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.push_display(field, value);
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.push_display(field, value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push_display(field, value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push_display(field, value);
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.push_display(field, value);
    }

    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        self.push_debug(field, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{EventCollector, LogLevel};
    use tokio::sync::broadcast;
    use tracing_subscriber::{layer::SubscriberExt, registry};

    #[test]
    fn collector_keeps_message_and_fields_inline() {
        let (tx, mut rx) = broadcast::channel(1);
        let collector = EventCollector::new(vec![tx]);
        let subscriber = registry().with(collector);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(answer = 42u64, kind = "demo", success = true, "hello");
        });

        let event = rx.try_recv().expect("expected collected log event");

        assert!(matches!(event.level, LogLevel::Info));
        assert!(event.msg.contains("hello"));
        assert!(event.msg.contains("answer=42"));
        assert!(event.msg.contains("kind=demo"));
        assert!(event.msg.contains("success=true"));
    }
}
