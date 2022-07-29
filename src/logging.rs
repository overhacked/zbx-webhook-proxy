use std::collections::HashMap;
use std::fs::File;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::io::{Write as _, self};

use time::{OffsetDateTime, Instant};
use time::{macros::format_description, format_description::FormatItem};
use tracing::field::Visit;
use tracing::{Subscriber, span, Span};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer,
    filter::LevelFilter,
    filter::Targets,
    fmt::{Layer as FmtLayer, MakeWriter},
    prelude::*,
    registry::LookupSpan, layer::Context,
};
use warp::trace::Info;

use crate::AppError;

const CLF_TIME: &[FormatItem] = format_description!("[day]/[month repr:short]/[year]:[hour repr:24]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]");
const HTTP_LOG_TARGET: &str = "warp::filters::trace";

pub(crate) fn setup(
    console_level: LevelFilter,
    access_log: &Option<PathBuf>,
) -> Result<Option<WorkerGuard>, AppError> {
    // Suppress HTTP request logging to console when
    // a file is configured
    let console_log = setup_console(console_level, access_log.is_none());

    let (access_log, worker_guard) = if let Some(file) = access_log {
        let (access_log, worker_guard) = setup_file(file)?;
        (Some(access_log), Some(worker_guard),)
    } else {
        (None, None,)
    };

    tracing_subscriber::registry()
        .with(console_log)
        .with(access_log)
        .try_init()?;
    Ok(worker_guard)
}

fn setup_console<S>(level: LevelFilter, enable_http: bool) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>
{
    let main_module = module_path!().split("::").next().unwrap();
    let default_level = level.min(LevelFilter::DEBUG);
    let http_level = if enable_http { default_level } else { LevelFilter::OFF };
    let filters = Targets::default()
        // Don't let the console default level
        // get more granular than Info, because
        // some libraries are VERY verbose (tokio_*)
        .with_default(default_level)
        // Allow this module and zbx_sender to
        // log at Trace and Debug
        .with_target(main_module, level)
        .with_target("zbx_sender", level)
        .with_target("test_mode", LevelFilter::INFO)
        .with_target(HTTP_LOG_TARGET, http_level);
    
    FmtLayer::default()
        .with_filter(filters)
}

fn setup_file<S>(file: &Path) -> Result<(impl Layer<S>, WorkerGuard), io::Error>
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    let filters = Targets::default()
        // Don't log anything from modules that aren't
        // specified with level_for()
        .with_default(LevelFilter::OFF)
        // HTTP requests must be logged with
        // target = [THIS MODULE]::http
        .with_target(HTTP_LOG_TARGET, LevelFilter::INFO);

    let (log_file, worker_guard) = tracing_appender::non_blocking(File::create(file)?);
    let log_layer = CombinedLogLayer::new(log_file).with_filter(filters);

    Ok((log_layer, worker_guard))
}

struct CombinedLogVisitor {
    start_instant: Instant,
    fields: HashMap<String, String>,
}

impl Default for CombinedLogVisitor {
    fn default() -> Self {
        let start_time = OffsetDateTime::now_local()
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let mut fields = HashMap::default();
        fields.insert(
            "start_time".into(),
            start_time.format(CLF_TIME).expect("failed to write timestamp"),
        );

        Self {
            start_instant: Instant::now(),
            fields,
        }
    }
}

impl Visit for CombinedLogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(field.to_string(), format!("{:?}", value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(field.to_string(), value.to_string());
    }
}

impl CombinedLogVisitor {
    fn get_field_value(&self, k: impl AsRef<str>) -> Option<&String> {
        self.fields.get(k.as_ref())
    }
}

struct CombinedLogLayer<
S,
W: for<'writer> MakeWriter<'writer> + 'static,
> {
    make_writer: W,
    _inner: PhantomData<fn(S)>,
}

impl<S, W> CombinedLogLayer<S, W>
where
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn new(make_writer: W) -> Self {
        Self {
            make_writer,
            _inner: Default::default(),
        }
    }
}

impl<S, W> Layer<S> for CombinedLogLayer<S, W>
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();
        if extensions.get_mut::<CombinedLogVisitor>().is_none()
        {
            extensions.insert(CombinedLogVisitor::default());
        }
        let entry = extensions.get_mut::<CombinedLogVisitor>().expect("just inserted");
        attrs.record(entry);
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.event_span(event) {
            let mut extensions = span.extensions_mut();
            if let Some(entry) = extensions.get_mut::<CombinedLogVisitor>() {
                event.record(entry);
            }
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("Span not found, this is a bug");
        let extensions = span.extensions();
        if let Some(entry) = extensions.get::<CombinedLogVisitor>() {
            let mut writer = self.make_writer.make_writer();
            let field_or_blank = |name| {
                entry.get_field_value(name).map_or("-", |s| s.as_str())
            };

            let elapsed = entry.start_instant.elapsed();
            let _ = writeln!(
                writer,
                r#"{} "-" "-" [{}] "{} {} {}" {} 0 "{}" "{}" {:.3}"#,
                field_or_blank("remote.addr"),
                field_or_blank("start_time"),
                field_or_blank("method"),
                field_or_blank("path"),
                field_or_blank("version"),
                field_or_blank("status"),
                field_or_blank("referer"),
                field_or_blank("user_agent"),
                elapsed.as_seconds_f64(),
            );
        }
    }
}

pub fn warp_trace(info: Info<'_>) -> Span {
    use tracing::field::{display, Empty};

    let span = tracing::info_span!(
        target: HTTP_LOG_TARGET,
        "request",
        remote.addr = Empty,
        method = %info.method(),
        path = %info.path(),
        version = ?info.version(),
        referer = Empty,
        user_agent = Empty,
    );

    // Record optional fields.
    if let Some(remote_addr) = info.remote_addr() {
        span.record("remote.addr", &display(remote_addr));
    }

    if let Some(referer) = info.referer() {
        span.record("referer", &display(referer));
    }

    if let Some(user_agent) = info.user_agent() {
        span.record("user_agent", &display(user_agent));
    }

    span
}
