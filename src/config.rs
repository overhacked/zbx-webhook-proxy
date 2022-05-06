use std::{net::{SocketAddr, Ipv6Addr}, path::PathBuf, str::FromStr, fs};

use clap::Parser;
use log::LevelFilter;
use serde::{Deserialize, Deserializer, de};
use warp::http::uri::PathAndQuery;

use crate::AppError;

type JmesPathExpression = jmespath::Expression<'static>;

#[derive(Parser, Clone, Debug)]
#[clap(about, author)]
struct Cli {
    #[clap(long = "config", short = 'c', parse(from_os_str), default_value = "/etc/getparams_to_zabbix.toml")]
    config_file: PathBuf,

    #[clap(long = "listen", short = 'l')]
    /// HTTP server listening address and port
    listen: Option<SocketAddr>,

    #[clap(long = "zabbix-server", short = 'z', display_order(1))]
    /// Zabbix Server address
    zabbix_server: Option<String>,

    #[clap(long = "zabbix-port", short = 'p', display_order(2))]
    /// Zabbix Server trapper port
    zabbix_port: Option<u16>,

    #[clap(long = "access-log", parse(from_os_str))]
    /// Log to a file in Apache Combined logging format
    access_log_path: Option<PathBuf>,

    #[clap(short, parse(from_occurrences = Cli::parse_verbosity))]
    /// Specify up to 3 times to increase console logging
    verbosity: LevelFilter,

    #[clap(long)]
    /// Run in test mode without sending actual values to Zabbix server
    test_mode: bool,
}

impl Cli {
    fn parse_verbosity(count: u64) -> LevelFilter {
        match count {
            0 => LevelFilter::Off,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    }
}

#[derive(Deserialize, Clone)]
 pub struct Config {
    #[serde(default = "Config::default_listen")]
    /// HTTP server listening address and port
    pub listen: SocketAddr,

    /// Zabbix Server address
    pub zabbix_server: Option<String>,

    #[serde(default = "Config::default_zabbix_port")]
    /// Zabbix Server trapper port
    pub zabbix_port: u16,

    /// Log to a file in Apache Combined logging format
    pub access_log_path: Option<PathBuf>,

    #[serde(deserialize_with = "Config::parse_log_level", default = "Config::default_log_level")]
    pub log_level: LevelFilter,

    pub routes: Vec<Route>,

    #[serde(skip, default)]
    pub test_mode: bool,
}

impl Config {
    fn default_listen() -> SocketAddr { (Ipv6Addr::LOCALHOST, 3030).into() }
    fn default_zabbix_port() -> u16 { 10051 }
    fn default_log_level() -> LevelFilter { LevelFilter::Warn }
    fn parse_log_level<'de, D>(deserializer: D) -> Result<LevelFilter, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        LevelFilter::from_str(&s)
            .map_err(|_| de::Error::custom("log_level value doesn't match any known log level"))
    }

    pub(crate) fn load() -> Result<Self, AppError> {
        let args = Cli::parse();
        let toml_file = fs::read_to_string(&args.config_file)?;
        let mut config: Self = toml::from_str(&toml_file)?;
        config.listen = args.listen.unwrap_or(config.listen);
        config.zabbix_server = args.zabbix_server.or(config.zabbix_server)
            .ok_or_else(|| AppError::ConfigMissingRequired("zabbix_server".into()))?
            .into();
        config.zabbix_port = args.zabbix_port.unwrap_or(config.zabbix_port);
        config.log_level = args.verbosity.max(config.log_level);
        config.access_log_path = args.access_log_path.or(config.access_log_path);
        config.test_mode = args.test_mode;
        Ok(config)
    }
}

#[derive(Deserialize, Clone)]
pub struct Route {
    #[serde(deserialize_with = "Route::parse_path")]
    /// Path on which to accept requests
    pub path: PathAndQuery,

    /// Host name for Zabbix Item (OPTIONAL) [default: reverse DNS or IP address of HTTP client]
    ///
    /// Host name the item belongs to (as registered in Zabbix frontend).
    pub item_host: Option<String>,

    // Using deserialize_with on an Option<T> means that default has to be
    // specified, or a missing field becomes an error. See
    // https://github.com/serde-rs/serde/issues/723#issuecomment-423299411
    #[serde(default, deserialize_with = "Route::parse_option_jmespath")]
    /// Dynamic field from request to determine host name for Zabbix Item.
    /// Can be a simple top-level field name or a JMESpath filter. In POSTed
    /// JSON data, the result must be a JSON string.
    /// [default: specified item_host or HTTP client address]
    pub item_host_field: Option<JmesPathExpression>,

    #[serde(default)]
    /// The field specified by item_host_field must be present in the request, or
    /// a warning will be logged and the request dropped.
    pub item_host_field_required: bool,

    /// Zabbix Item key. The special value "*" means expand all top
    /// level keys in the request data to individual Zabbix item keys.
    pub item_key: String,

    // See comment above about "redundant" serde(default)
    #[serde(default, deserialize_with = "Route::parse_option_jmespath")]
    /// JMESpath filter to be applied to data before forwarding to Zabbix.
    /// GET parameters are transformed from key=value... to {"key": "value",...}
    /// and can be filtered as normal JSON.
    /// POSTed JSON data can be filtered directly.
    pub json_filter: Option<JmesPathExpression>,
}

impl Route {
    fn parse_path<'de, D>(deserializer: D) -> Result<PathAndQuery, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        PathAndQuery::from_str(&s) 
            .map_err(de::Error::custom)
            .and_then(|path| match path.query() {
                Some(q) => Err(de::Error::custom(format!("route path may not contain the query string `{}`", q))),
                None => Ok(path),
            })
    }

    fn parse_option_jmespath<'de, D>(deserializer: D) -> Result<Option<JmesPathExpression>, D::Error>
        where D: Deserializer<'de>
    {
        let maybe_s: Option<String> = Option::deserialize(deserializer)?;
        let maybe_jmespath = match maybe_s {
            None => None,
            Some(s) => {
                let j = jmespath::compile(&s)
                    .map_err(de::Error::custom)?;
                Some(j)
            },
        };
        Ok(maybe_jmespath)
    }
}
