# Architecture

Receive-side capture adapters produce `TrafficEvent` metadata. `SlidingWindow`
handles late/out-of-order/duplicate events. `extract_features` creates a common
feature map, while protocol parsers add independent evidence. Model adapters are
failure-isolated and outputs pass through normalization and weighted fusion. The
risk engine applies configurable thresholds and persistence. Alerts are hash chained
before SQLite persistence and published to WebSockets. The UI is read-only.

The core path has no ACK, DNS, remote API, reverse path, active probe, or inline
modification dependency.
