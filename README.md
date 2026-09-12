# DIODESHIELD

DIODESHIELD is a runnable, receive-side, passive OT traffic detection prototype for a
hardware data-diode architecture. It uses metadata and optional protocol observations only;
it does not send packets, probe assets, modify traffic, or require a return path.

## Quick start

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e ".[dev,ml]"
python training/train_all_models.py --synthetic
python -m diodeshield.cli --scenario beacon
uvicorn diodeshield.api.main:app --reload
```

Open `http://localhost:8000/dashboard/index.html` (or `http://localhost:8000/dashboard/`) when serving the repository, or use
the API at `/docs`. One-command 90-second demo:
- **Windows PowerShell**: `.\demo.ps1`
- **Linux/macOS**: `./demo.sh`
- **Docker**: `docker compose up --build`.


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

- **5-Branch AI Threat Detection**: Real model inference across all five branches:
  - **XGBoost**: Supervised gradient-boosted decision trees trained on synthetic telemetry, with live **TreeSHAP** feature attribution.
  - **LSTM (PyTorch)**: Recurrent temporal neural network scoring sequence window anomalies.
  - **Spectral FFT**: Signal-frequency analysis detecting periodic polling and C2 beaconing rhythms.
  - **Kitsune (Adapted KitNET)**: Calibrated baseline autoencoder tracking multi-variate reconstruction error.
  - **Isolation Forest (scikit-learn)**: Unsupervised ensemble isolation measuring high-dimensional feature outliers.
- **Weighted Multi-Branch Fusion**: Dynamic score normalization, disagreement quantification, and calibrated weighted fusion.
- **Traffic Scenarios**: Differentiated evaluation scenarios: `normal` (OT Modbus polling with 0 false positives), `beacon` (C2 channel with TreeSHAP explainability), `recon` (industrial scanning/fan-out), and `protocol` (Modbus malformations).
- **Cryptographic Hash Chain**: SHA-256 tamper-evident append-only evidence ledger linking every alert with sequence continuity and cryptographic verification API (`/api/integrity`).
- **Explainability**: Integrated TreeSHAP on XGBoost with deterministic fallback attributions highlighting positive and negative feature contributions.
- **SOC Web Dashboard**: Real-time static dashboard featuring WebSocket live updates, alert triage inspector, multi-model voting progress bars, TreeSHAP contribution waterfalls, and tamper-evident chain verification badges.
- **Passive OT Capture**: Strictly zero-transmission receive-side architecture; zero packets injected, zero ACKs, no probing.
- **Controlled Mitigation**: Windows Defender Firewall integration strictly disabled by default (`DIODESHIELD_FIREWALL_BLOCKING=true`), requiring administrator privilege and explicit confirmation.

## Prototype / experimental limitations

- **Synthetic Evaluation Notice**: Models are prototype-trained on synthetic, metadata-only lab data for architecture validation and jury demonstration. They are not trained on live classified OT traffic.
- **Production Dataset Contract**: Production training requires open-license datasets meeting `training/DATASET_CONTRACT.md` specifications (cryptographic SHA-256 manifest check, schema validation, temporal split); unverified datasets are rejected.
- **Passive Operation**: All analysis is passive and receive-side only. No packets are transmitted, no return channel is assumed, and physical diode boundaries are respected.
- **Explainability**: Confidence represents inter-model consensus, not Bayesian posterior probability. Findings are triage leads, not standalone proof of compromise.
- **Platform Scope**: Automated host firewall actions target Windows (`netsh advfirewall`); live packet capture requires TShark with Npcap on Windows or libpcap on Linux. Without capture tools, DIODESHIELD operates in synthetic evaluation/replay mode.

