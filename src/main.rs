mod config;
mod handlers;
mod filters;
mod logging;
mod zabbix;

use log::{info, error};
pub(crate) use serde_json::{json, Value as JsonValue};
use std::io;
use std::sync::Arc;
use warp::Filter;
use thiserror::Error;
use trust_dns_resolver::{error::ResolveError, TokioAsyncResolver as AsyncResolver};

use crate::config::Config;
use crate::zabbix::ZabbixLogger;

type ZabbixItemValue = (String, String,);

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let config = Config::load()?;

    logging::setup(
        config.log_level,
        &config.access_log_path,
    )?;

    if let Some(path) = &config.access_log_path {
        info!("Logging HTTP requests to {}", path.display());
    }

    // The Zabbix connector must live inside Arc
    // because each warp request thread concurrently
    // borrows it
    let zabbix =
        Arc::new(ZabbixLogger::new(config.zabbix_server.expect("Config invariant"), config.zabbix_port));
    let resolver = AsyncResolver::tokio_from_system_conf()?;

    let mut route_filters = None;
    for route in config.routes {
        info!("Listening to requests on path `{}`", &route.path);
        let route_filter = filters::make_path_filter(route.path.as_str())
            .map(move || route.clone());

        match route_filters.take() {
            None => {
                route_filters = Some(route_filter.boxed());
            },
            Some(f) => {
                route_filters = Some(f.or(route_filter).unify().boxed());
            },
        }
    }

    let context = handlers::AppContext {
        zabbix: Arc::clone(&zabbix),
        resolver: resolver.clone(),
        test_mode: config.test_mode,
    };
    let routes = route_filters.expect("Config invariant")
        .and(filters::with_context(context))
        .and(warp::addr::remote())
        .and(filters::get().or(filters::post()).unify())
        .and_then(handlers::handle_request)
        .recover(handlers::handle_errors)
        .with(warp::log::custom(logging::warp_combined));

    warp::serve(routes).run(config.listen).await;
    Ok(())
}

#[derive(Error, Debug)]
enum AppError {
    #[error(transparent)]
    LoggingInit(#[from] fern::InitError),
    #[error(transparent)]
    ResolverInit(#[from] ResolveError),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ConfigSyntaxError(#[from] toml::de::Error),
    #[error("required setting `{0}` not present in configuration file")]
    ConfigMissingRequired(String),
}
