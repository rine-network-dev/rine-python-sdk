# Changelog

All notable changes to the `rine` Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1]

### Added

- `MessageType.WEBHOOK` (`"rine.v1.webhook"`). An inbound webhook delivered through
  the rine Funnel arrives as a `rine.v1.webhook` message; consumers can now filter on
  the named constant instead of the literal string. Receiving already worked, since
  `MessageRead.type` is an open string.

## [0.3.0]

- Baseline for this changelog. Earlier releases predate it.
