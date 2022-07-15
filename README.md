# zbx-webhook-proxy

Accepts requests on a configurable set of URLs then forwards the GET query parameters or POSTed JSON body to Zabbix Server (as a JSON value), with optional [JMESPath](https://jmespath.org) transformation.

Use with Zabbix 4.0 or later and [Trapper Items](https://www.zabbix.com/documentation/6.0/en/manual/config/items/itemtypes/trapper) of type `log`, then configure further processing of the JSON body in Zabbix using [Dependent Items](https://www.zabbix.com/documentation/6.0/en/manual/config/items/itemtypes/dependent_items) and [JSON preprocessing](https://www.zabbix.com/documentation/6.0/en/manual/config/items/preprocessing/jsonpath_functionality).

## Built With

* [warp](https://crates.io/crates/warp) - A super-easy, composable, web server framework for warp speeds 
* [zbx-sender](https://crates.io/crates/zbx_sender) - Modern Rust implementation of Zabbix Sender Client
* [trust-dns-resolver](https://crates.io/crates/trust-dns-resolver) - Used for reverse DNS resolution not supported by `std::net`
* [clap](https://crates.io/crates/clap) - Parse command line arguments by defining a struct 
* [fern](https://crates.io/crates/fern) - “Simple, efficent logging”; manages console logs and optional access log file
* [serde-json](https://crates.io/crates/serde_json) - for `json!()` happiness

## Version History

See changes in [CHANGELOG.md](CHANGELOG.md)

## Building

### Prerequisites

Rust 2021 edition

### Installation
1. `cargo build --release`
2. Copy `target/release/zbx-webhook-proxy` to any executable location and configure startup

### TODO
- Startup scripts and SystemD unit files
- `make install`

## Configuration

### `config.toml` file

See [`example_config.toml`](example_config.toml) for full usage

**Minimal configuration**
```toml
zabbix_server = "zabbix.example.com"

[[route]]
path = "/hook"
item_host = "Monitored Host"
item_key = "event.json"
```

### Command Line
*All command-line flags are optional but can be specified to override the configuration file or defaults*

#### Flags with no default value
*MUST be specified on the command line or in the configuration file*
- `-z/--zabbix-server`: Address of Zabbix Server or Proxy<br>

#### Flags with a default value
- `-c/--config`: Path to `config.toml` (default `/etc/zbx-webhook-proxy.toml`)
- `-p/--zabbix-port`: Zabbix trapper port (default: 10051)
- `-l/--listen`: Proxy HTTP listening port (default: 3030)

#### Flags that enable additional features
- `--access-log`: Path to a log file that will contain requests in Apache Common log format

#### Flags that enable features only available from the command line
- `--test-mode`: Accept webhooks and print values that would be sent to Zabbix Server without actually sending
- `-v/--verbose`: Increase logging to the console for troubleshooting purposes

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/overhacked/zbx-webhook-proxy/tags). 

## Authors

* **Ross Williams** - 🐙[GitHub](https://github.com/overhacked) &mdash; 🐦[Twitter](https://twitter.com/overhacked)

## License

This project is licensed under the Modified BSD License - see the [LICENSE](LICENSE) file for details
