# getparam-to-zabbix

Accepts requests on a given URI and forwards the query parameters to Zabbix Server as a JSON string.
Intended for use with a `log` item type and Zabbix 4.0 and later's dependent item JSON pre-processing.

## Getting Started

`cargo build`

### Prerequisites

Rust 2018 edition

## Built With

* [warp](https://crates.io/crates/warp) - A super-easy, composable, web server framework for warp speeds 
* [zbx\_sender](https://crates.io/crates/zbx_sender) - Modern Rust implementation of Zabbix Sender Client
* [dns-lookup](https://crates.io/crates/dns-lookup) - Used for reverse DNS resolution not supported by `std::net`
* [structopt](https://crates.io/crates/structopt) - Parse command line arguments by defining a struct 
* [fern](https://crates.io/crates/fern) - “Simple, efficent logging”; manages console logs and optional access log file
* [serde\_json](https://crates.io/crates/serde_json) - for `json!()` happiness

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/overhacked/getparams-to-zabbix/tags). 

## Authors

* **Ross Williams** - *Initial work* - [Overhacked](https://github.com/overhacked)

## License

This project is licensed under the Modified BSD License - see the [LICENSE](LICENSE) file for details
