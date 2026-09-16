# DIODESHIELD 🛡️

> **Production Real-Time Network Security Monitoring & Cyber-Threat Detection Platform**  
> *Smart India Hackathon PS-26145 | Organization: NTRO (National Technical Research Organisation)*

---

## 1. Executive Summary

**DIODESHIELD** is an enterprise-ready, production-grade real-time network security monitoring and cyber-threat detection platform.

The system operates exclusively on **real network traffic and authentic telemetry** captured dynamically from physical and virtual host network interfaces (Ethernet, Wi-Fi, Loopback, virtual adapters). All simulated, fabricated, dummy, and synthetic traffic components have been completely eliminated.

Key architectural guarantees:
* **Real Packet & Flow Ingestion**: Dynamic network interface enumeration via Npcap/Scapy with asynchronous ring-buffered queueing to capture line-rate network traffic without packet loss or blocking.
* **Layered Multi-Engine Detection**: Operates 5 complementary detection layers simultaneously:
  1. *Signature Engine*: Deterministic, versioned rules with MITRE ATT&CK mappings (Xmas scans, Null scans, SYN-FIN probes, industrial OT protocol violations).
  2. *Behavioral Detector*: Stateful entity tracking for vertical port scans, horizontal subnet sweeps, C2 beaconing via inter-arrival interval jitter clustering, and connection storms.
  3. *Statistical Anomaly Engine*: Time-aware, host-aware Exponentially Weighted Moving Average (EWMA) and dynamic rolling z-scores derived from observed telemetry.
  4. *Threat Intelligence Correlation*: Real-time IP reputation lookups querying live feeds (Tor Project bulk exit directory, AbuseIPDB v2, AlienVault OTX) with TTL-based caching and rate limiting.
  5. *Multi-Model AI Consensus*: 5-branch ensemble (XGBoost, LSTM, Spectral FFT, Kitsune, Isolation Forest) with TreeSHAP explainability.
* **Cryptographic Tamper-Evidence**: Unbroken SHA-256 evidence hash chain linking every detected security alert to its predecessor, guaranteeing audit immutability.
* **Zero-Synthetic Honesty**: When an interface is idle, the dashboard and APIs display `"No live traffic detected"`, never generating fake packets or placeholder statistics.

---

## 2. Production Architecture

```text
       [ Real Network Interface (Wi-Fi / Ethernet / Loopback) ]
                                  │
                                  ▼
                   [ Live Packet Sniffer (Npcap/Scapy) ]
                     (Async Worker + Bounded Ring-Buffer)
                                  │
                                  ▼
                     [ Protocol Packet Decoder ]
             (IPv4, IPv6, TCP Flags, UDP, ICMP, DNS, TLS SNI)
                                  │
                                  ▼
               [ Bidirectional Session Flow Engine ]
                  (5-tuple tracking, TCP FSM, PPS, BPS)
                                  │
        ┌─────────────────────────┴─────────────────────────┐
        ▼                                                   ▼
[ Layered Detection Engine ]                    [ Dynamic Feature Engine ]
  ├── 1. Signature Engine (Rules, ATT&CK)         ├── Volumetric & Temporal
  ├── 2. Behavioral Engine (Scans, Beaconing)     ├── Spatial Entropy
  ├── 3. Statistical Baseline (EWMA, Z-Score)     └── Spectral FFT Frequencies
  ├── 4. Real Threat Intel (Tor, AbuseIPDB)                 │
  └── 5. Machine Learning (5 AI Models)                     ▼
        │                                       [ Multi-Model AI Inference ]
        │                                       (XGBoost, LSTM, FFT, Kitsune, IF)
        └─────────────────────────┬─────────────────────────┘
                                  ▼
               [ Correlation & Deduplication Engine ]
               (Multi-signal clustering, Alert grouping)
                                  │
                                  ▼
             [ Cryptographic SHA-256 Hash Chain Ledger ]
               (Immutable append-only SQLite evidence DB)
                                  │
                                  ▼
                 [ Real-Time SOC Dashboard & API ]
               (WebSocket streaming, Real telemetry charts)
```

---

## 3. Core Subsystems

### A. Real-Time Packet Capture (`diodeshield/capture/`)
* **Dynamic Interface Discovery**: Discovers all active network interfaces with human-readable descriptions, IPv4/IPv6 addresses, MAC addresses, and link speeds.
* **Non-Blocking Architecture**: High-priority sniffer pushes raw packets into a bounded ring-buffer queue (`queue.Queue(maxsize=20000)`). A dedicated worker thread decodes and routes events asynchronously without dropping packets under burst conditions.
* **Live Telemetry Metrics**: Calculates continuous Packets Per Second (PPS), Bits Per Second (BPS), total packets processed, dropped packet counters, and queue depths.

### B. Packet Decoder (`diodeshield/decoder/`)
* Full dissection of IPv4 and IPv6 headers.
* Transport layer parsing: TCP flags (SYN, ACK, FIN, RST, PSH, URG), sequence numbers, acknowledgement numbers, and window sizes.
* Application protocol identification: HTTP, HTTPS, DNS (query names, record types), TLS (Server Name Indication without payload decryption), and industrial protocols (Modbus/TCP, S7comm, DNP3, IEC-104).

### C. Bidirectional Flow Engine (`diodeshield/flow_engine/`)
* Reconstructs bidirectional communication sessions indexed by normalized 5-tuples `(src_ip, dst_ip, src_port, dst_port, protocol)`.
* Tracks forward/backward packet counts, forward/backward byte volumes, inter-arrival time distributions, and TCP state machine transitions (`SYN_SENT`, `SYN_RCVD`, `ESTABLISHED`, `FIN_WAIT`, `RESET`).

### D. Layered Threat Detection (`diodeshield/detection/`)
1. **Signature Engine**: Versioned rules mapped to MITRE ATT&CK techniques:
   * `SIG-SCAN-001`: TCP Xmas Scan (FIN+PSH+URG flags)
   * `SIG-SCAN-002`: TCP Null Scan (zero flags probe)
   * `SIG-SCAN-003`: Illegal TCP SYN-FIN scan probe
   * `SIG-DOS-001`: High-frequency TCP SYN flood
   * `SIG-OT-001`: Unauthorized Modbus coil/register modification (0x05, 0x06, 0x0F, 0x10)
   * `SIG-OT-002`: S7comm PLC CPU Stop command
   * `SIG-NET-001`: Insecure cleartext administration (Telnet port 23)
2. **Behavioral Detector**:
   * *Vertical Port Scan*: Source probing $> 20$ destination ports within 2 seconds.
   * *Horizontal Subnet Sweep*: Source sweeping $> 15$ destination IPs on the same port within 2 seconds.
   * *C2 Beaconing*: Detects periodic communications with low inter-arrival jitter coefficient of variation ($CV < 0.15$).
   * *Connection Storms*: Detects abnormal bursts of TCP RSTs and unanswered connection attempts.
3. **Statistical Baseline Engine**:
   * Computes EWMA mean and variance continuously on real traffic rates.
   * Generates dynamic rolling z-scores ($z \ge 3.0$ = warning, $z \ge 5.0$ = critical) without relying on arbitrary fixed constants.
4. **Threat Intelligence Client**:
   * Live lookup against AbuseIPDB v2 and official Tor Project bulk exit node directory.
   * TTL-based local caching (24 hours) and token-bucket rate limiting.
   * Strict attribution: unknown/clean IPs are marked `NEUTRAL`, never falsely flagged as malicious.
5. **Correlation Engine**:
   * Combines signatures, behavioral anomalies, and threat intelligence matches for the same host into correlated security incidents.
   * Sliding-window deduplication prevents alert storms during network bursts.

---

## 4. Quick Start Guide

### Prerequisites
* Python 3.11+ (Windows, Linux, or macOS)
* Npcap (Windows) or `libpcap` (Linux) for promiscuous packet capture.

### 1. Installation

```powershell
# Clone the repository
git clone https://github.com/Puneeth-S88/diodeshield-demo-artifacts.git
cd diodeshield-demo-artifacts

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # On Linux/macOS: source .venv/bin/activate

# Install dependencies
pip install -e .[ml]
```

### 2. Configuration (`.env`)

Copy `.env.example` to `.env` and configure your preferences:

```ini
DIODESHIELD_INTERFACE=auto
DIODESHIELD_LIVE_CAPTURE=true
DIODESHIELD_DB=data/diodeshield.db
DIODESHIELD_API_KEY=your-secure-api-key
DIODESHIELD_JWT_SECRET=your-jwt-secret
ABUSEIPDB_API_KEY=your-optional-abuseipdb-key
```

### 3. Start the Production Server

```powershell
.\.venv\Scripts\python.exe -m uvicorn diodeshield.api.main:app --host 127.0.0.1 --port 8000
```

Access the SOC Web Dashboard at: **`http://127.0.0.1:8000/dashboard/`**  
Access the interactive OpenAPI Docs at: **`http://127.0.0.1:8000/docs`**

---

## 5. Production CLI Usage

The system includes a production CLI utility (`diodeshield.cli`):

```powershell
# List available network interfaces
python -m diodeshield.cli --list-interfaces

# Run real-time packet capture in terminal
python -m diodeshield.cli --capture --interface auto

# Verify unbroken SHA-256 evidence chain integrity
python -m diodeshield.cli --check-integrity

# Check IP threat intelligence reputation
python -m diodeshield.cli --threat-intel 185.220.101.5

# Display database metrics
python -m diodeshield.cli --db-metrics
```

---

## 6. REST & WebSocket API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health, sensor status, PPS, and database state |
| `GET` | `/health/detailed` | Component health across capture, flow engine, TI, and models |
| `GET` | `/api/interfaces` | Enumerate available physical and virtual network interfaces |
| `POST` | `/api/capture/select` | Admin endpoint to dynamically bind capture to an interface |
| `POST` | `/api/capture/start` | Start live packet capture |
| `POST` | `/api/capture/stop` | Pause live packet capture |
| `GET` | `/api/capture/stats` | Real-time PPS, BPS, total packets, and drop statistics |
| `GET` | `/api/flows` | Active bidirectional network flow sessions |
| `GET` | `/api/alerts` | Filterable security alert history |
| `GET` | `/api/alerts/{id}/validation` | Alert explanation, TreeSHAP attributions, and hash verification |
| `GET` | `/api/threat-intel/lookup/{ip}` | Query IP threat reputation with source attribution |
| `GET` | `/api/threat-intel/status` | Status of external threat intelligence feeds |
| `GET` | `/api/rules` | List versioned detection rules and ATT&CK techniques |
| `GET` | `/api/system/metrics` | Host CPU, RAM, process threads, and queue telemetry |
| `GET` | `/api/integrity` | Verifies continuity of the SHA-256 evidence chain |
| `WS` | `/ws/alerts` | Real-time WebSocket push stream for alerts and telemetry |

---

## 7. Testing & Verification

All automated tests are strictly isolated inside `tests/` and do not affect production telemetry:

```powershell
# Run the complete test suite (31 tests)
pytest tests/ -v
```

Verification suite coverage:
* `test_interface_discovery`: Validates interface enumeration.
* `test_packet_decoder`: Validates IPv4/IPv6, TCP flags, DNS, and TLS decoding.
* `test_flow_tracker`: Validates bidirectional session aggregation.
* `test_signatures`: Validates detection of Xmas, Null, and OT write attacks.
* `test_behavioral`: Validates port scans, sweeps, and C2 beaconing detection.
* `test_anomaly_baseline`: Validates EWMA updates and z-score deviation triggers.
* `test_threat_intel`: Validates caching and private IP filtering.
* `test_correlation`: Validates alert deduplication and multi-signal clustering.
* `test_auth_rbac`: Validates JWT token generation and role authorization.
* `test_api_*`: Validates REST API endpoints and telemetry responses.

---

## 8. License

Apache 2.0. Developed for the Smart India Hackathon (SIH0145 / NTRO PS-26145).
