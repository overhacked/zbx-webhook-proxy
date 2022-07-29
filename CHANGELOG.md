# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] 2022-07-29
### Changed
- Updated to `zbx-sender-rs` 0.3.0, to address some vulnerabilities in
  transitive dependencies of that crate
- Switched from `logging` crate to `tracing` crate for console
  output and HTTP access logging. HTTP access log format remains
  the same; only the internal implementation has changed
- Console debugging output is richer and can be in color, showing
  message levels and module location of events
### Added
- Documented `"*"` value for `item_key` configuration, which expands each
  top-level key in the JSON object of a request to a separate Item in Zabbix.
  See [example configuration](example_config.yaml) for details.

## [0.2.0] 2022-07-18
### Added
- TOML configuration format
- Support for multiple URIs
- [JMESPath](https://jmespath.org) filtering and transformation of request data
- Dynamic hostname based on request data or reverse DNS

## [0.1.0-alpha] 2019-10-20
### First Release
- Support only GET parameters
- Send to Zabbix as a JSON hash, one key per parameter
- Access log in Apache Common format to a separate file
