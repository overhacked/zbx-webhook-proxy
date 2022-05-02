use chrono::Utc;
use clap::Parser;
use dns_lookup::lookup_addr;
use log::{debug, info, log, LevelFilter, warn};
use serde_json::{json, Value as JsonValue};
use warp::Rejection;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use warp::{
    self, Filter, Reply,
    http::StatusCode,
};
use thiserror::Error;

use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
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

fn setup_logging(
    console_level: log::LevelFilter,
    access_log: &Option<PathBuf>,
) -> Result<(), fern::InitError> {
    let mut loggers = fern::Dispatch::new();

    let mut console_log = setup_console_log(console_level);

    if let Some(file) = access_log {
        // Suppress HTTP request logging to console when
        // a file is configured
        console_log = console_log.level_for(format!("{}::http", module_path!()), LevelFilter::Off);
        let access_log = setup_access_log(file)?;
        loggers = loggers.chain(access_log);
    };

    loggers = loggers.chain(console_log);

    loggers.apply()?;
    Ok(())
}

fn setup_console_log(level: log::LevelFilter) -> fern::Dispatch {
    let limit_to_info = || match level {
        LevelFilter::Debug | LevelFilter::Trace => LevelFilter::Info,
        _ => level,
    };
    fern::Dispatch::new()
        // Don't let the console default level
        // get more granular than Info, because
        // some libraries are VERY verbose (tokio_*)
        .level(limit_to_info())
        // Allow this module and zbx_sender to
        // log at Trace and Debug
        .level_for(module_path!(), level)
        .level_for("zbx_sender", level)
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}][{}] {}",
                Utc::now().format("%Y-%m-%d %H:%M:%S %z"),
                record.level(),
                record.target(),
                message,
            ))
        })
        .chain(std::io::stdout())
}

fn setup_access_log(file: &Path) -> Result<fern::Dispatch, fern::InitError> {
    let access_log = fern::Dispatch::new()
        // Log the HTTP requests without modification,
        // because warp handles the log line formatting
        .format(|out, message, _| out.finish(format_args!("{}", message,)))
        // Don't log anything from modules that aren't
        // specified with level_for()
        .level(LevelFilter::Off)
        // HTTP requests must be logged with
        // target = [THIS MODULE]::http
        .level_for(format!("{}::http", module_path!()), LevelFilter::Info)
        .chain(fern::log_file(file)?);
    Ok(access_log)
}

fn log_warp_combined(info: warp::filters::log::Info) {
    // Increase log level for server and client errors
    let status = info.status();
    let level = if status.is_server_error() {
        log::Level::Error
    } else if status.is_client_error() {
        log::Level::Warn
    } else {
        log::Level::Info
    };
    log!(
        target: &format!("{}::http", module_path!()),
        level,
        // Apache Combined Log Format: https://httpd.apache.org/docs/2.4/logs.html#combined
        "{} \"-\" \"-\" [{}] \"{} {} {:?}\" {} 0 \"{}\" \"{}\" {:?}",
        info.remote_addr()
            .map_or(String::from("-"), |a| format!("{}", a.ip())),
        Utc::now().format("%d/%b/%Y:%H:%M:%S %z"),
        info.method(),
        info.path(),
        info.version(),
        status.as_u16(),
        info.referer().unwrap_or("-"),
        info.user_agent().unwrap_or("-"),
        info.elapsed(),
    );
}

#[tokio::main]
async fn main() -> Result<(), fern::InitError> {
    let args = Cli::parse();

    setup_logging(
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
    let context = AppContext {
        in_test: args.test_mode,
        zabbix: Arc::clone(&zabbix),
        zabbix_host: args.zabbix_item_host,
        zabbix_key: args.zabbix_item_key,
    };

    let routes = path_filter
        .and(with_context(context))
        .and(remote_addr())
        .and(get().or(post()).unify())
        .and_then(handle_request_params)
        .recover(handle_request_error)
        .with(warp::log::custom(log_warp_combined));

    warp::serve(routes).run(args.listen).await;
    Ok(())
}

fn with_context(ctx: AppContext) -> impl Filter<Extract = (AppContext,), Error = Infallible> + Clone {
    warp::any().map(move || ctx.clone())
}

fn remote_addr() -> impl Filter<Extract = (IpAddr,), Error = Rejection> + Clone {
    // Get the remote socket address tuple
    warp::addr::remote()
        .and_then(|addr_option: Option<SocketAddr>| async move { match addr_option {
            // Fail with an error if the client address is not available
            Some(addr) => Ok(addr.ip()),
            None => Err(warp::reject::custom(RequestError::MissingClientAddr)),
        }})
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

async fn handle_request_params(
    ctx: AppContext,
    remote_addr: IpAddr,
    json: JsonValue,
) -> Result<impl Reply, Rejection> {
    // Use hostname if specified on the command line.
    // Otherwise, try to lookup the client's hostname
    // in DNS; fail gracefully to client IP as a string
    let host = match ctx.zabbix_host {
        Some(ref s) => s.to_owned(),
        None => lookup_addr(&remote_addr).unwrap_or(format!("{}", &remote_addr)),
    };

    // Send to Zabbix
    if ctx.in_test {
        warn!("would send value to Zabbix {{{}:{}}}: `{}`", &host, &ctx.zabbix_key, &json.to_string());
        return Ok(warp::reply::with_status(String::from(""), StatusCode::NO_CONTENT));
    }

    let zbx_result = ctx.zabbix.log(&host, &ctx.zabbix_key, &json.to_string());
    match zbx_result {
        Ok(res) => {
            match res.failed_cnt() {
                None => Err(warp::reject::custom(RequestError::ZabbixBadReply)), // StatusCode::INTERNAL_SERVER_ERROR
                Some(n) if n > 0 => Err(warp::reject::custom(RequestError::ZabbixItemsFailed(n))), // StatusCode::BAD_REQUEST
                _ => Ok(warp::reply::with_status(String::from(""), StatusCode::NO_CONTENT)),
            }
        }
        Err(err) => Err(warp::reject::custom(RequestError::ZabbixError(err.to_string()))), // StatusCode::BAD_GATEWAY
    }
}

async fn handle_request_error(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if let Some(e) = err.find::<RequestError>() {
        use RequestError::*;
        (code, message) = match e {
            MissingClientAddr => (StatusCode::BAD_REQUEST, "MISSING_CLIENT_ADDR",),
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
    in_test: bool,
    zabbix: Arc<ZabbixLogger>,
    zabbix_host: Option<String>,
    zabbix_key: String,
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
enum RequestError {
    #[error("the client's remote address was not available")]
    MissingClientAddr,
    #[error("Zabbix returned a non-number where the failed count should have been")]
    ZabbixBadReply,
    #[error("Zabbix failed {0} items in the request")]
    ZabbixItemsFailed(i32),
    #[error("{0}")]
    ZabbixError(String),
}

impl warp::reject::Reject for RequestError {}
