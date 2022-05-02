use std::path::{Path, PathBuf};

use chrono::Utc;
use log::{log, LevelFilter};

pub fn setup(
    console_level: log::LevelFilter,
    access_log: &Option<PathBuf>,
) -> Result<(), fern::InitError> {
    let mut loggers = fern::Dispatch::new();

    let mut console_log = setup_console(console_level);

    if let Some(file) = access_log {
        // Suppress HTTP request logging to console when
        // a file is configured
        console_log = console_log.level_for(format!("{}::http", module_path!()), LevelFilter::Off);
        let access_log = setup_file(file)?;
        loggers = loggers.chain(access_log);
    };

    loggers = loggers.chain(console_log);

    loggers.apply()?;
    Ok(())
}

fn setup_console(level: log::LevelFilter) -> fern::Dispatch {
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

fn setup_file(file: &Path) -> Result<fern::Dispatch, fern::InitError> {
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

pub fn warp_combined(info: warp::filters::log::Info) {
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

