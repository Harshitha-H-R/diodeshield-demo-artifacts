# DIODESHIELD

DIODESHIELD is a runnable, receive-side, passive OT traffic detection prototype for a
hardware data-diode architecture. It uses metadata and optional protocol observations only;
it does not send packets, probe assets, modify traffic, or require a return path.

## Quick start

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m diodeshield.cli --scenario protocol
uvicorn diodeshield.api.main:app --reload
```

Open `http://localhost:8000/dashboard/index.html` when serving the repository, or use
the API at `/docs`. One command demo: `./demo.sh` (PowerShell users can run the three
CLI commands shown above). Docker: `docker compose up --build`.

Live, read-only host monitoring starts automatically when the service starts.
Install Wireshark/TShark with Npcap on Windows (or TShark on Linux), then
start Uvicorn. `DIODESHIELD_INTERFACE=auto` discovers the first non-loopback
interface; set an exact interface number/name when needed. Set
`DIODESHIELD_LIVE_CAPTURE=false` to disable it. The worker only reads packet
metadata and the dashboard refreshes continuously; it does not inject, alter,
or block packets. Without TShark or capture permission, health reports
`capture_unavailable` and the API remains usable.

Traffic generated from a Kali machine is visible only when this laptop is on
the traffic path (for example, the Kali target is this laptop), the switch/AP
mirrors the traffic to the capture interface, or the interface is configured
for authorized promiscuous monitoring. Capturing on this laptop cannot observe
arbitrary traffic between other hosts across a switched network.

The dashboard's **Validate alerts** view shows the alert evidence, model
scores, feature contributions, and hash-chain data. Firewall actions are
disabled by default and are never automatic. To deliberately apply a
validated source-IP block on Windows, run the service with administrator
rights and set `DIODESHIELD_FIREWALL_BLOCKING=true`; the action requires
`confirm=true`, refuses loopback/unspecified/multicast addresses, and records
an audit entry. The resulting Windows Defender Firewall rule drops matching
inbound packets. Test this only on a system where blocking that IP is
authorized.

Safe lab evaluation can be repeated with:

```bash
python training/train_all_models.py --synthetic
python scripts/udp_flood_lab.py --packets 500 --rate 250
python scripts/offline_threat_lab.py --scenario behavior --count 1200
```

The synthetic harness uses metadata-only examples and is marked evaluation-only.
It does not craft malformed packets or send traffic beyond localhost. Production
training is a separate fail-closed workflow:

```bash
python training/train_all_models.py --dataset data/training/dataset.csv \
  --manifest training/dataset_manifest.json --output-dir models --download
```

It refuses files without an open-license provenance record, checksum, finite
numeric schema, labels, and temporal/group split field. See
`training/DATASET_CONTRACT.md` for the exact ingestion contract. No production
model is trained in the checked-in workspace; the uploaded CSV has unverified
provenance and is intentionally rejected.

## Implemented

Synthetic normal/beacon/recon/protocol scenarios; JSON/Pydantic ingestion; tolerant
sliding windows; spatial, volumetric, temporal, FFT and topology features; Modbus/TCP
metadata parser; Zeek `conn.log` and optional TShark JSON replay; deterministic model
adapters (XGBoost/LSTM/FFT/DIODESHIELD-adapted KitNET fallback/Isolation Forest);
score normalization/fusion/disagreement; receive-side IP identity mismatch,
packet-alteration/checksum metadata, and packet-behavior detections; deterministic
feature explanations with an explicit optional-SHAP upgrade path; risk thresholds and
persistence; SQLite evidence tables; SHA-256 hash chain; FastAPI REST, WebSockets,
health and feedback; a dependency-free static dashboard; Docker Compose; tests and
training entry points.

## Prototype / experimental limitations

The default adapters are deterministic fallbacks, not trained production models.
Optional scikit-learn, XGBoost and PyTorch interfaces are intentionally isolated and
require labelled data and validation before use. The KitNET adapter is explicitly
DIODESHIELD-adapted and does not bundle third-party Kitsune code. DNP3, IEC-104 and
S7comm are metadata-only extension points. Zeek/TShark/dumpcap integrations consume
exported rows and are not required for the synthetic demo. IP spoofing and packet
alteration findings require capture-provided identity/checksum/hash evidence; they do
not claim to prove an attack. Explanations are deterministic fallback attributions
unless a validated TreeSHAP model is explicitly integrated. Confidence means model
agreement, not calibrated attack probability. No CVE, gateway management attack, or
physical diode failure is inferred without telemetry.

See `configs/default.yaml`, the API OpenAPI document, and `training/` for extension
points. Retention, authentication/RBAC, Prometheus export, full calibration, and
PostgreSQL migration are planned hardening work.
