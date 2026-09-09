# Technical document audit

The implementation was checked against `DIODESHIELD_Technical_Document.pdf`
(version 2.0) and the requested safety boundary.

| Document requirement | Current implementation |
| --- | --- |
| Passive, one-way receive-side processing | `TrafficEvent` metadata pipeline; no reverse-path or control-plane action |
| Zeek structured telemetry | `diodeshield.ingestion.zeek.read_zeek_conn` reads `conn.log` TSV and keeps flow metadata |
| TShark support | Optional read-only JSON replay and payload-field filtering in `capture/tshark_manager.py` |
| 5-second/1-second windows, FFT | `SlidingWindow` plus NumPy FFT and timing features |
| XGBoost | Deterministic fallback is always available; a validated optional XGBoost artifact can be configured |
| LSTM and Kitsune/KitNET | Deterministic sequence/online warm-up adapters; no third-party Kitsune code is bundled |
| SHAP explanations | Alerts persist per-model deterministic attributions; optional TreeSHAP is used when a compatible tree artifact and `shap` are installed |
| Spoofing, alteration, behavior detections | Metadata-only identity mismatch, checksum/hash alteration evidence, fan-out/volume/behavior scoring |
| Safe validation | Offline lab scenarios (`spoof`, `altered`, `behavior`, `flood`, `ttl`) and bounded localhost-only UDP demo |

The detections are indicators, not cryptographic proof of compromise. Spoofing
and alteration findings require capture-provided evidence such as an observed
source mismatch or checksum/hash marker. Production scores, thresholds,
latency, capture loss, and plant-specific false-positive rates still require
validated labeled data and hardware testing, as specified by the document.
