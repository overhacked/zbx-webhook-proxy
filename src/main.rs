mod config;
mod logging;

use config::Route;
use log::{debug, info, warn, error};
use serde_json::{json, Value as JsonValue};
use warp::Rejection;
use std::{collections::BTreeMap, io};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::{
    self, Filter, Reply,
    http::StatusCode,
};
use thiserror::Error;
use trust_dns_resolver::{error::ResolveError, TokioAsyncResolver};

use crate::config::Config;

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
        Arc::new(ZabbixLogger::new(config.zabbix_server.expect("runtime guarantee"), config.zabbix_port));
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

    let mut route_filter = None;
    for route in config.routes {
        info!("Listening to requests on path `{}`", &route.path);
        let path = route.path.as_str().trim_start_matches('/').to_string();
        let path_filter = if path.is_empty() {
            warp::path::end().boxed()
        } else {
            warp::path(path).and(warp::path::end()).boxed()
        };
        let path_filter = path_filter.map(move || route.clone());

        match route_filter.take() {
            None => {
                route_filter = Some(path_filter.boxed());
            },
            Some(f) => {
                route_filter = Some(f.or(path_filter).unify().boxed());
            },
        }
    }

    let context = AppContext {
        zabbix: Arc::clone(&zabbix),
        resolver: resolver.clone(),
    };
    let routes = route_filter.unwrap()
        .and(with_context(context))
        .and(warp::addr::remote())
        .and(get().or(post()).unify())
        .and_then(handle_request)
        .recover(handle_errors)
        .with(warp::log::custom(logging::warp_combined));

    warp::serve(routes).run(config.listen).await;
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
    route: Route,
    ctx: AppContext,
    addr_option: Option<SocketAddr>,
    json: JsonValue,
) -> Result<impl Reply, Rejection> {
    let remote_host = resolve_item_host(&route, &ctx, &addr_option, &json).await?;

    let payload = match &route.json_filter {
        Some(f) => {
            let jmespath_result = f.search(json).map_err(RequestError::from)?;
            if jmespath_result.is_null() {
                error!("the configured filter [{}] doesn't match any data in the request", f);
                return Err(RequestError::NoFilterMatch.into());
            }
            json!(jmespath_result)
        },
        None => json,
    };

    send_to_zabbix(&route, &ctx, &remote_host, payload).await?;
    Ok(warp::reply::with_status(String::from(""), StatusCode::NO_CONTENT))
}

async fn resolve_item_host(
    route: &Route,
    ctx: &AppContext,
    addr_option: &Option<SocketAddr>,
    json: &JsonValue,
) -> Result<String, Rejection> {
    // Is --zabbix-item-host-field specified?
    if let Some(pat) = &route.item_host_field {
        match resolve_dynamic_host(pat, json).await? {
            // Can the requested field be found in the GET params or POST body?
            Some(h) =>
                return Ok(h),
            // Otherwise, abort with an error if --host-field-required is set
            None if route.item_host_field_required =>
                return Err(RequestError::MissingHostField.into()),
            // If --host-field-required not set, then continue below
            None =>
                info!("Specified host field `{}` is not present", pat),
        }
    }

    if let Some(host) = &route.item_host {
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
    let field = match field.as_string() {
        Some(s) if s.is_empty() => {
            warn!("Specified host field `{}` is present but is an empty string", pattern);
            None
        },
        Some(s) => Some(s.to_owned()),
        None => {
            // Warn on wrong field type, but quietly pass along None for null
            if !field.is_null() {
                warn!("Specified host field `{}` is present but is not a string (found type {})", pattern, field.get_type());
            }
            None
        }
    };
    Ok(field)
}

async fn send_to_zabbix(route: &Route, ctx: &AppContext, host: &str, data: JsonValue) -> Result<(), RequestError> {
    let values = if route.item_key == "*" {
        data.as_object()
            .ok_or(RequestError::WildcardKeyOnNonObject)?
            .into_iter()
            .map(|v| (v.0.to_string(), stringify_zabbix_value(v.1),))
            .collect()
    } else {
        vec![(route.item_key.clone(), data.to_string(),)]
    };

    // If running in test mode, log what would be sent to zabbix to the console,
    // and return as if successful.
    // TODO: reimplement test_mode
    // if ctx.route.test_mode {
    //     warn!("would send values to Zabbix: (Host = {}) {:?}", host, values);
    //     return Ok(())
    // }

    match ctx.zabbix.log_many(host, values) {
        Ok(res) => {
            match res.failed_cnt() {
                None => Err(RequestError::ZabbixBadReply),
                Some(n) if n > 0 => Err(RequestError::ZabbixItemsFailed(n)),
                _ => Ok(()),
            }
        }
        Err(err) => {
            error!("Zabbix error: {}", err);
            Err(RequestError::ZabbixError(err.to_string()))
        },
    }
}

fn stringify_zabbix_value(value: &JsonValue) -> String {
    if let Some(s) = value.as_str() {
        s.to_string()
    } else if let Some(b) = value.as_bool() {
        let bool_as_int_str = if b { "1" } else { "0" };
        bool_as_int_str.to_string()
    } else {
        value.to_string()
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
            NoFilterMatch => (StatusCode::BAD_REQUEST, "MISSING_FILTER_DATA",),
            ZabbixBadReply => (StatusCode::INTERNAL_SERVER_ERROR, "ZABBIX_REPLY_INVALID",),
            ZabbixItemsFailed(_) => (StatusCode::BAD_REQUEST, "ZABBIX_ITEMS_FAILED",),
            ZabbixError(_) => (StatusCode::BAD_GATEWAY, "ZABBIX_ERROR",),
            WildcardKeyOnNonObject => (StatusCode::BAD_REQUEST, "DATA_NOT_AN_OBJECT",),
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

    fn log_many(&self,
        host: &str,
        values: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>
    )
        -> zbx_sender::Result<zbx_sender::Response>
    {
        let values: Vec<zbx_sender::SendValue> = values.into_iter()
            .map(|i| (host, i.0.as_ref(), i.1.as_ref(),).into())
            .collect();

        debug!("sending to Zabbix `{:?}`", values);
        self.sender.send(values)
    }

    // fn log(&self, host: &str, key: &str, value: &str) -> zbx_sender::Result<zbx_sender::Response> {
    //     self.log_many(host, [(key, value,)])
    // }
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

#[derive(Error, Debug)]
enum RequestError {
    #[error("the client's remote address was not available")]
    MissingClientAddr,
    #[error(transparent)]
    JmespathError(#[from] jmespath::JmespathError),
    #[error("the request parameters do not contain the host field")]
    MissingHostField,
    #[error("the supplied filter did not return any data from the request")]
    NoFilterMatch,
    #[error("the item key was specified as a wildcard ('*') but the supplied item value was not a JSON object")]
    WildcardKeyOnNonObject,
    #[error("Zabbix returned a non-number where the failed count should have been")]
    ZabbixBadReply,
    #[error("Zabbix failed {0} items in the request")]
    ZabbixItemsFailed(i32),
    #[error("{0}")]
    ZabbixError(String),
}

impl warp::reject::Reject for RequestError {}
