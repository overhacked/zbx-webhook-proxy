mod config;
mod handlers;
mod filters;
mod logging;
mod zabbix;

use simple_eyre::eyre::Result;
use log::{info, error};
pub(crate) use serde_json::{json, Value as JsonValue};
use std::io;
use std::sync::Arc;
use warp::Filter;
use thiserror::Error;
use trust_dns_resolver::{error::ResolveError, TokioAsyncResolver as AsyncResolver};

use crate::config::Config;
use crate::zabbix::ZabbixLogger;
pub use crate::zabbix::ZabbixItemValue;

#[tokio::main]
async fn main() -> Result<()> {
    simple_eyre::install()?;
    let config = Config::load()?;

    logging::setup(
        config.log_level,
        &config.access_log_path,
    )?;

    if let Some(path) = &config.access_log_path {
        info!("Logging HTTP requests to {}", path.display());
    }

    // The Zabbix connector must live inside Arc because it is not Clone
    let zabbix = Arc::new(
        ZabbixLogger::new(config.zabbix_server.expect("Config invariant"), config.zabbix_port)
    );
    // The AsyncResolver IS Clone but should live inside Arc to allow
    // efficient resolver caching, otherwise every resolver.clone()
    // copies the entire cache
    let resolver = Arc::new(
        AsyncResolver::tokio_from_system_conf()?
    );

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
        resolver: Arc::clone(&resolver),
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
    #[error("Failed to load configuration file at `{path}`")]
    ConfigLoadError {
        path: String,
        source: io::Error
    },
    #[error(transparent)]
    ConfigSyntaxError(#[from] toml::de::Error),
    #[error(
        "Required setting `{0}` not present \
        in configuration file or on command line"
    )]
    ConfigMissingRequired(String),
}
