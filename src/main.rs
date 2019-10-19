use chrono::Utc;
use dns_lookup::lookup_addr;
use log::{debug, info, log, trace, LevelFilter};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use structopt::StructOpt;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::{self, path, Filter, Reply};

use fern;
use std::path::{Path, PathBuf};
use std::io::{Error, ErrorKind};

#[derive(StructOpt, Debug)]
#[structopt(name = "serve")]
struct Cli {
    #[structopt(long = "listen", short = "l", default_value = "[::1]:3030")]
    listen: std::net::SocketAddr,

    #[structopt(long = "zabbix-server", short = "z")]
    zabbix_server: String,

    #[structopt(long = "zabbix-port", short = "p", default_value = "10051")]
    zabbix_port: u16,

    #[structopt(long = "host", short = "s")]
    zabbix_item_host: Option<String>,

    #[structopt(long = "key", short = "k")]
    zabbix_item_key: String,

    #[structopt(long = "access-log", short = "L", parse(from_os_str))]
    /// Log to a file in Apache Combined logging format
    access_log_path: Option<PathBuf>,

    #[structopt(short, parse(from_occurrences))]
    /// Specify up to 3 times to increase console logging
    verbosity: u8,
}

fn setup_logging(
    console_level: log::LevelFilter,
    access_log: Option<PathBuf>,
) -> Result<(), fern::InitError> {
    let mut loggers = fern::Dispatch::new();

    let mut console_log = setup_console_log(console_level);

    if let Some(file) = access_log {
        console_log = console_log.level_for(format!("{}::http", module_path!()), LevelFilter::Off);
        let access_log = setup_access_log(&file)?;
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
        .level(limit_to_info())
        .level_for("tokio_reactor", limit_to_info())
        .level_for("warp", limit_to_info())
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
        .format(|out, message, _| out.finish(format_args!("{}", message,)))
        .level(LevelFilter::Off)
        .level_for(format!("{}::http", module_path!()), LevelFilter::Info)
        .chain(fern::log_file(file)?);
    Ok(access_log)
}

fn log_warp_combined(info: warp::filters::log::Info) {
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

fn main() -> Result<(), fern::InitError> {
    let args = Cli::from_args();

    setup_logging(
        match args.verbosity {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        },
        args.access_log_path,
    )?;

    let log = warp::log::custom(log_warp_combined);

    info!(
        "Zabbix Server at {}:{}",
        &args.zabbix_server, args.zabbix_port
    );
    let zabbix: Arc<ZabbixLogger> =
        Arc::new(ZabbixLogger::new(&args.zabbix_server, args.zabbix_port));
    let iaevent = path("IAEvents")
        .and(warp::get2())
        .and(handle_iaevent(
            Arc::clone(&zabbix),
            args.zabbix_item_host,
            args.zabbix_item_key,
        ))
        .with(log);

    warp::serve(iaevent).run(args.listen);
    Ok(())
}

fn handle_iaevent(
    zabbix: Arc<ZabbixLogger>,
    zabbix_host: Option<String>,
    zabbix_key: String,
) -> BoxedFilter<(impl Reply,)> {
    warp::addr::remote()
        .and_then(|addr_option: Option<SocketAddr>| match addr_option {
            Some(addr) => Ok(addr.ip()),
            None => Err(warp::reject::custom(Error::new(ErrorKind::AddrNotAvailable, "The client's remote address was not available"))),
        })
        .and(warp::query::<BTreeMap<String, String>>())
        .map(move |remote: IpAddr, params| {
            let j = json!(params);
            let host = match zabbix_host {
                Some(ref s) => s.to_owned(),
                None => lookup_addr(&remote).unwrap_or(format!("{}", &remote)),
            };
            zabbix.log(&host, &zabbix_key, &j.to_string())
        })
        .map(
            |zbx_result: zbx_sender::Result<zbx_sender::Response>| match zbx_result {
                Ok(res) => {
                    match res.failed_cnt() {
                        None => warp::reply::with_status(
                            String::from("Zabbix returned a non-number where the failed count should have been: {}"),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                        Some(n) if n > 0 => warp::reply::with_status(
                            format!("Zabbix failed to process {} items", n),
                            StatusCode::BAD_REQUEST,
                        ),
                        _ => warp::reply::with_status(String::from(""), StatusCode::NO_CONTENT),
                    }
                }
                Err(err) => warp::reply::with_status(err.to_string(), StatusCode::BAD_GATEWAY),
            },
        )
        .boxed()
}

struct ZabbixLogger {
    sender: zbx_sender::Sender,
}

impl ZabbixLogger {
    fn new(server: &str, port: u16) -> ZabbixLogger {
        ZabbixLogger {
            sender: zbx_sender::Sender::new(server.to_owned(), port),
        }
    }

    fn log(&self, host: &str, key: &str, value: &str) -> zbx_sender::Result<zbx_sender::Response> {
        trace!("sending value to Zabbix {{{}:{}}}: `{}`", host, key, value);
        self.sender.send((host, key, value))
    }
}
