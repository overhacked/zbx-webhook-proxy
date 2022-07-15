# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
