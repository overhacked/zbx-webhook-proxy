use std::{sync::Arc, net::SocketAddr, convert::Infallible};

use thiserror::Error;
use log::{info, warn, error};
use warp::{http::StatusCode, Rejection, Reply};

use crate::{AsyncResolver, config::Route, json, JsonValue, zabbix::ZabbixLogger, ZabbixItemValue};

#[derive(Clone)]
pub struct AppContext {
    pub zabbix: Arc<ZabbixLogger>,
    pub resolver: Arc<AsyncResolver>,
    pub test_mode: bool,
}

pub async fn handle_request(
    route: Route,
    ctx: AppContext,
    addr_option: Option<SocketAddr>,
    json: JsonValue,
) -> Result<impl Reply, Rejection> {
    let remote_host = resolve_item_host(&route, &ctx.resolver, &addr_option, &json).await?;

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

    let item_values = compose_zabbix_kv_tuples(&route.item_key, &payload)?;
    // If running in test mode, log what would be sent to zabbix to the console,
    // and return as if successful.
    if ctx.test_mode {
        warn!("would send values to Zabbix: (Host = {}) {:?}", remote_host, item_values);
    } else {
        send_to_zabbix(ctx.zabbix, &remote_host, item_values).await?;
    }

    Ok(warp::reply::with_status(String::from(""), StatusCode::NO_CONTENT))
}

async fn resolve_item_host(
    route: &Route,
    resolver: &AsyncResolver,
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
        let lookup_result = resolver.reverse_lookup(addr).await;
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

fn compose_zabbix_kv_tuples(key: &str, data: &JsonValue) -> Result<Vec<ZabbixItemValue>, RequestError> {
    let values = if key == "*" {
        data.as_object()
            .ok_or(RequestError::WildcardKeyOnNonObject)?
            .into_iter()
            .map(|v| ZabbixItemValue {
                key: v.0.to_string(),
                value: stringify_zabbix_value(v.1),
            })
            .collect()
    } else {
        vec![ZabbixItemValue {
            key: key.to_owned(),
            value: data.to_string(),
        }]
    };
    Ok(values)
}

async fn send_to_zabbix(zabbix: Arc<ZabbixLogger>, host: &str, values: Vec<ZabbixItemValue>) -> Result<(), RequestError> {
    match zabbix.log_many(host, values) {
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

pub async fn handle_errors(err: Rejection) -> Result<impl Reply, Infallible> {
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
