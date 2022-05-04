mod logging;

use clap::Parser;
use log::{debug, info, LevelFilter, warn};
use serde_json::{json, Value as JsonValue};
use warp::Rejection;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use warp::{
    self, Filter, Reply,
    http::StatusCode,
};
use thiserror::Error;
use trust_dns_resolver::{error::ResolveError, TokioAsyncResolver};

use std::path::PathBuf;

#[derive(Parser, Clone, Debug)]
#[clap(about, author)]
struct Cli {
    #[clap(long = "listen", short = 'l', default_value = "[::1]:3030")]
    /// HTTP server listening address and port
    listen: std::net::SocketAddr,

    #[clap(long = "path", short = 'P', default_value = "/", validator(validate_listen_path))]
    /// Path on which to accept requests
    listen_path: warp::http::uri::PathAndQuery,

    #[clap(long = "zabbix-server", short = 'z', display_order(1))]
    /// Zabbix Server address
    zabbix_server: String,

    #[clap(long = "zabbix-port", short = 'p', default_value = "10051", display_order(2))]
    /// Zabbix Server trapper port
    zabbix_port: u16,

    #[clap(long = "host", short = 's', display_order(4))]
    /// Host name for Zabbix Item (OPTIONAL) [default: reverse DNS or IP address of HTTP client]
    ///
    /// Host name the item belongs to (as registered in Zabbix frontend).
    zabbix_item_host: Option<String>,

    #[clap(long = "dynamic-host", short = 'S', display_order(5), parse(try_from_str = jmespath::compile))]
    /// Dynamic field from request to determine host name for Zabbix Item
    /// [default: specified --host or HTTP client address]
    zabbix_item_host_field: Option<jmespath::Expression<'static>>,

    #[clap(long = "dynamic-host-required", display_order(6), requires = "zabbix-item-host-field")]
    /// The field specified by --dynamic-host must be present in the request parameters, or
    /// a warning will be logged and the request dropped.
    host_field_required: bool,

    #[clap(long = "key", short = 'k', display_order(3))]
    /// Zabbix Item key
    zabbix_item_key: String,

    #[clap(long = "access-log", short = 'L', parse(from_os_str))]
    /// Log to a file in Apache Combined logging format
    access_log_path: Option<PathBuf>,

    #[clap(short, parse(from_occurrences))]
    /// Specify up to 3 times to increase console logging
    verbosity: u8,

    #[clap(long)]
    /// Run in test mode without sending actual values to Zabbix server
    test_mode: bool,
}

fn validate_listen_path(path_arg: &str) -> Result<(), String> {
    match warp::http::uri::PathAndQuery::from_str(path_arg) {
        Ok(path) => match path.query() {
            Some(qs) => Err(format!("Listen path may not contain the query string `{}`", qs)),
            None => Ok(()),
        },
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let args = Cli::parse();

    logging::setup(
        match args.verbosity {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        },
        &args.access_log_path,
    )?;

    if let Some(path) = &args.access_log_path {
        info!("Logging HTTP requests to {}", path.display());
    }

    // The Zabbix connector must live inside Arc
    // because each warp request thread concurrently
    // borrows it
    let zabbix: Arc<ZabbixLogger> =
        Arc::new(ZabbixLogger::new(&args.zabbix_server, args.zabbix_port));

    info!("Listening to requests on path `{}`", &args.listen_path);
    let listen_path = args.listen_path.as_str().trim_start_matches('/').to_owned();
    let path_filter = if !listen_path.is_empty() {
        warp::path::param()
        .and(warp::path::end())
        .and_then(move |request_path: String| {
            let listen_path = listen_path.clone();
            async move {
                if request_path == listen_path {
                    Ok(())
                } else {
                    Err(warp::reject::not_found())
                }
            }
        })
        // Following consumes 0-tuple result from above
        // and untuple_one() removes it from the chain
        .map(|_| {}).untuple_one()
        .boxed()
    } else {
        warp::path::end().boxed()
    };

    let listen = args.listen;
    let context = AppContext {
        zabbix: Arc::clone(&zabbix),
        resolver: TokioAsyncResolver::tokio_from_system_conf()?,
        args,
    };

    let routes = path_filter
        .and(with_context(context))
        .and(warp::addr::remote())
        .and(get().or(post()).unify())
        .and_then(handle_request)
        .recover(handle_errors)
        .with(warp::log::custom(logging::warp_combined));

    warp::serve(routes).run(listen).await;
    Ok(())
}

fn with_context(ctx: AppContext) -> impl Filter<Extract = (AppContext,), Error = Infallible> + Clone {
    warp::any().map(move || ctx.clone())
}

fn get() -> impl Filter<Extract = (JsonValue, ), Error = Rejection> + Clone {
    warp::get()
        // Put GET params into a BTreeMap so they become sorted
        .and(warp::query::<BTreeMap<String, String>>())
        .map(|params| json!(params))
}

fn post() -> impl Filter<Extract = (JsonValue, ), Error = Rejection> + Clone {
    warp::post()
        .and(warp::body::json::<JsonValue>())
}

async fn handle_request(
    ctx: AppContext,
    addr_option: Option<SocketAddr>,
    json: JsonValue,
) -> Result<impl Reply, Rejection> {
    let remote_host = resolve_item_host(&ctx, &addr_option, &json).await?;
    send_to_zabbix(&ctx, &remote_host, &json.to_string()).await

}

async fn resolve_item_host(
    ctx: &AppContext,
    addr_option: &Option<SocketAddr>,
    json: &JsonValue,
) -> Result<String, Rejection> {
    // Is --zabbix-item-host-field specified?
    if let Some(pat) = &ctx.args.zabbix_item_host_field {
        if let Some(h) = resolve_dynamic_host(pat, json).await? {
            // Can the requested field be found in the GET params or POST body?
            return Ok(h);
        } else if ctx.args.host_field_required {
            // Otherwise, abort with an error if --host-field-required is set
            return Err(RequestError::MissingHostField.into());
        } else {
            // If --host-field-required not set, then continue below
        }
    }

    if let Some(host) = &ctx.args.zabbix_item_host {
        // Is a static --zabbix-item-host set?
        Ok(host.to_owned())
    } else if let Some(addr) = addr_option {
        // Otherwise, try to resolve the client's address to
        // a DNS name and fall back to just using the IP
        let addr = addr.ip();
        let lookup_result = ctx.resolver.reverse_lookup(addr).await;
        let host_ptr = lookup_result
            // Convert Ok into Some(PTR result), Err into None
            .iter()
            // Create an iterator over reverse_lookup results,
            // and flatten with above Iter over Result
            .flat_map(|r| r.iter())
            // Convert result to string, and trim trailing '.'
            .map(|v| v.to_string().trim_end_matches('.').to_owned())
            // Get the first result (should be only one for PTR records)
            .next();

        // Use Some(PTR result) or fall back to the IP address as String
        let host = host_ptr.unwrap_or_else(|| addr.to_string());

        Ok(host)
    } else {
        // Unlikely, but if all ways of determining the item
        // host are unavailable, abort with an error
        Err(RequestError::MissingClientAddr.into())
    }
}

async fn resolve_dynamic_host(
    pattern: &jmespath::Expression<'_>,
    json: &JsonValue,
) -> Result<Option<String>, RequestError> {
    let field = pattern.search(json)?;

    // Ensure result of JMESPath query is a non-empty string
    if field.is_null() {
        info!("Specified host field `{}` is not present", pattern);
    }

    let field = match field.as_string() {
        Some(s) if s.is_empty() => {
            warn!("Specified host field `{}` is present but is an empty string", pattern);
            None
        },
        Some(s) => Some(s.to_owned()),
        None => {
            warn!("Specified host field `{}` is present but is not a string (found type {})", pattern, field.get_type());
            None
        }
    };
    Ok(field)
}

async fn send_to_zabbix(ctx: &AppContext, host: &str, data: &str) -> Result<impl Reply, Rejection> {
    let success_reply = warp::reply::with_status(String::from(""), StatusCode::NO_CONTENT);

    // If running in test mode, log what would be sent to zabbix to the console,
    // and return as if successful.
    if ctx.args.test_mode {
        warn!("would send value to Zabbix {{{}:{}}}: `{}`", host, &ctx.args.zabbix_item_key, data);
        return Ok(success_reply);
    }

    let zbx_result = ctx.zabbix.log(host, &ctx.args.zabbix_item_key, data);
    match zbx_result {
        Ok(res) => {
            match res.failed_cnt() {
                None => Err(RequestError::ZabbixBadReply.into()),
                Some(n) if n > 0 => Err(RequestError::ZabbixItemsFailed(n).into()),
                _ => Ok(success_reply),
            }
        }
        Err(err) => Err(RequestError::ZabbixError(err.to_string()).into()),
    }
}

async fn handle_errors(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if let Some(e) = err.find::<RequestError>() {
        use RequestError::*;
        (code, message) = match e {
            MissingClientAddr => (StatusCode::BAD_REQUEST, "MISSING_CLIENT_ADDR",),
            JmespathError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "JMESPATH_ERROR",),
            MissingHostField => (StatusCode::BAD_REQUEST, "MISSING_HOST_FIELD",),
            ZabbixBadReply => (StatusCode::INTERNAL_SERVER_ERROR, "ZABBIX_REPLY_INVALID",),
            ZabbixItemsFailed(_) => (StatusCode::BAD_REQUEST, "ZABBIX_ITEMS_FAILED",),
            ZabbixError(_) => (StatusCode::BAD_GATEWAY, "ZABBIX_ERROR",),
        };
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "UNHANDLED_ERROR";
    }

    let json = warp::reply::json(&json!({
        "code": code.as_u16(),
        "message": message,
    }));

    Ok(warp::reply::with_status(json, code))
}

#[derive(Clone)]
struct AppContext {
    zabbix: Arc<ZabbixLogger>,
    resolver: TokioAsyncResolver,
    args: Cli,
}

struct ZabbixLogger {
    sender: zbx_sender::Sender,
}

impl ZabbixLogger {
    fn new(server: impl Into<String>, port: u16) -> Self {
        let server = server.into();

        info!(
            "Logging to Zabbix Server at {}:{}",
            server, port
        );
        Self {
            sender: zbx_sender::Sender::new(server, port),
        }
    }

    fn log(&self, host: &str, key: &str, value: &str) -> zbx_sender::Result<zbx_sender::Response> {
        debug!("sending value to Zabbix {{{}:{}}}: `{}`", host, key, value);
        self.sender.send((host, key, value))
    }
}

#[derive(Error, Debug)]
enum AppError {
    #[error(transparent)]
    LoggingInit(#[from] fern::InitError),
    #[error(transparent)]
    ResolverInit(#[from] ResolveError),
}

#[derive(Error, Debug)]
enum RequestError {
    #[error("the client's remote address was not available")]
    MissingClientAddr,
    #[error(transparent)]
    JmespathError(#[from] jmespath::JmespathError),
    #[error("the request parameters do not contain the host field")]
    MissingHostField,
    #[error("Zabbix returned a non-number where the failed count should have been")]
    ZabbixBadReply,
    #[error("Zabbix failed {0} items in the request")]
    ZabbixItemsFailed(i32),
    #[error("{0}")]
    ZabbixError(String),
}

impl warp::reject::Reject for RequestError {}
