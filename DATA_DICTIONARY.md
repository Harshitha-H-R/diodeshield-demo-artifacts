# Data dictionary

`TrafficEvent` contains timestamp, endpoint/port metadata, protocol, packet
length, optional header observations, a source label and optional asset ID.
Feature windows contain volume, temporal/IAT, spatial, FFT and topology values,
plus `behavior_anomaly_score`, `ip_spoofing_score`, `packet_alteration_score`, and
`payload_integrity_anomaly`. These detection fields are metadata-only indicators:
they require capture observations such as an observed/expected source mismatch,
checksum status, or an explicit payload/hash mismatch marker.

Alerts include raw and normalized model scores, disagreement, risk level,
protocol evidence, baseline deviation, top feature evidence, model/schema/config
versions, a deterministic per-model explanation (or a future TreeSHAP result), and
a SHA-256 evidence-chain link. Payload is not stored by default.
