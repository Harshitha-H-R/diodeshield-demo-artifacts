# DIODESHIELD Production Training & Threat Analysis Guide

## Overview

DIODESHIELD has been upgraded with a production-grade training pipeline and comprehensive threat scenario collection. This document describes data ingestion, model training, threat analysis, and validation.

## Training Pipeline

### Synthetic Lab Training (Safe Metadata-Only)

Run safe synthetic training evaluation:

```bash
python training/train_all_models.py --synthetic
```

This generates `reports/synthetic_training_report.json` with:
- 40 synthetic samples (10 normal, 30 attack)
- Model evaluations for: XGBoost, LSTM, FFT, Kitsune, Isolation Forest
- Safety: metadata-only; no packet crafting; no external traffic
- **Status**: Evidence-only, NOT production training

### Production Training (Requires Verified Dataset)

Production training requires a dataset manifest with verified provenance:

```bash
python training/train_all_models.py --dataset data/training/dataset.csv --manifest training/dataset_manifest.json --download
```

**Requirements** (fail closed):
1. Public `source_url` with direct download capability
2. Reviewed open license (CC0, CC-BY, Apache-2.0, BSD, ODC, public domain)
3. SHA-256 checksum of exact downloaded file
4. Binary label column (0/1)
5. Numeric feature columns
6. Temporal or group-aware split (enforces reproducibility)

**Outputs** (on success):
- Trained model artifacts in `models/` (JSON format)
- `models/production_training_report.json` with:
  - Metrics: ROC-AUC, PR-AUC, precision, recall, F1, latency percentiles
  - Calibration parameters (Platt scaling)
  - Threshold selection
  - Full provenance (dataset, license, split, timestamp)
  - Artifact integrity (SHA-256)

**Current Status**: No public dataset manifest configured; production training is not run by default.

## Threat Scenario Collection & Analysis

Comprehensive threat data collection with model analysis across 10 attack categories:

```bash
python training/collect_training_data.py --output reports/threat_analysis_report.json
```

### Scenarios Included

1. **Normal**: HTTP/HTTPS traffic patterns (100 samples)
2. **UDP Burst**: UDP flood attack simulation (80 samples)
3. **TCP Scan**: Port scanning reconnaissance (60 samples)
4. **DNS Tunnel**: DNS exfiltration attempt (40 samples)
5. **Lateral Movement**: Network propagation (50 samples)
6. **Protocol Anomaly**: Malformed protocol usage - Modbus (45 samples)
7. **Data Exfiltration**: Large transfer anomaly (35 samples)
8. **Resource Exhaustion**: CPU/memory pressure (30 samples)
9. **Beaconing**: C&C command & control (25 samples)
10. **Encryption Anomaly**: Unexpected tunneling (20 samples)

**Output**: `reports/threat_analysis_report.json`
- Per-scenario model score analysis (mean, std, min, max)
- Aggregate metrics (total 485 samples, 385 attacks, 100 normal)
- Safety: metadata-only; no packet generation; loopback-safe

## Model Training Status

### Currently Implemented Branches

| Model | Status | Backend | Version | Training Status |
|-------|--------|---------|---------|-----------------|
| XGBoost | Fallback | Deterministic | fallback-tabular-0.1 | Not trained (optional ml extra required) |
| LSTM | Fallback | Deterministic | fallback-sequence-0.1 | Not trained (optional torch required) |
| FFT | Streaming | Dependency-free | signal-0.1 | Ready for production training |
| Kitsune | Adapted | Deterministic | diodeshield-adapted-kitnet-fallback-0.1 | Ready for production training |
| Isolation Forest | Fallback | Deterministic | fallback-0.1 | Not trained (optional ml extra required) |

### Production Training Gaps

- **XGBoost, LSTM, Isolation Forest**: Require optional `[ml]` dependencies and validated labeled data
- **FFT, Kitsune**: Streaming-compatible; ready for production training with verified dataset
- **All branches**: Require explicit dataset contract with source URL, license, checksum, temporal/group split

## Model Inference at Runtime

All models are **always available** at inference time:

```python
from diodeshield.models.adapters import enabled_adapters
from diodeshield.features.builder import extract_features

adapters = enabled_adapters(config)  # All 5 branches loaded
features = extract_features(events)
scores = {name: adapter.score(features) for name, adapter in adapters.items()}
```

**Fallback Behavior**:
- If an optional dependency is missing (e.g., XGBoost), the adapter uses deterministic fallback
- Fallback scores are bounded [0, 1] and represent evidence, not calibrated probability
- Dashboard clearly labels each model's backend and training status

## API Integration

### Model Health Endpoint

```bash
curl http://localhost:8000/api/models
```

Returns:
```json
[
  {
    "model_name": "xgboost",
    "model_version": "fallback-tabular-0.1",
    "backend": "deterministic",
    "feature_schema_version": "1.0.0",
    "training_status": "not_trained",
    "provenance": null
  },
  ...
]
```

### Training Provenance

Once production training succeeds, artifacts include:

```json
{
  "model_name": "fft",
  "model_version": "fft-production-1.0.0",
  "training_status": "trained",
  "provenance": {
    "dataset_name": "UNSW-NB15",
    "source_url": "https://...",
    "license": "CC-BY-4.0",
    "sha256": "...",
    "training_timestamp": "2026-09-09T...",
    "split": "temporal"
  },
  "metrics": {
    "roc_auc": 0.92,
    "pr_auc": 0.88,
    "precision": 0.89,
    "recall": 0.85,
    "f1": 0.87,
    "latency_ms_p50": 1.2,
    "latency_ms_p95": 3.5
  }
}
```

## Dashboard Enhancements

The SOC dashboard now includes:

### KPI Cards
- Total alerts, Critical/High alerts, Traffic volume, Unique sources, Average confidence

### Time Series
- Alert volume (24h hourly)
- Traffic volume (24h hourly)
- Severity breakdown
- Attack category distribution

### Entity Analysis
- Top flagged sources & destinations
- Protocol distribution
- Anomaly score heatmap

### Model Health
- Live model status (backend, version, latency)
- Training provenance for each branch
- Clear labeling: "trained" vs "not_trained" vs "fallback"

### Filtering & Reporting
- Filter alerts by severity, category, source, destination
- Generate time-bounded reports with JSON export
- Alert detail view with full feature analysis

## Validation & Testing

Run comprehensive validation:

```bash
python tests/validate_all.py
```

**Test Coverage**:
- ✅ Linting (ruff import sorting)
- ✅ PyTest regression suite (9 tests, 100% pass)
- ✅ Synthetic training end-to-end
- ✅ Model adapters (all 5 branches load and score)
- ✅ Pipeline processing (events → alerts)
- ✅ Threat scenario collection (10 scenarios, 485 samples)
- ✅ API endpoints (6 core endpoints)

**Result**: All tests PASS

## Data Safety & Governance

### What DIODESHIELD Does NOT Do

- ❌ Crafts malformed packets
- ❌ Sends live traffic
- ❌ Modifies network traffic
- ❌ Requires return path (receive-only)
- ❌ Uses random row splits (enforces temporal/group-aware splits)
- ❌ Labels synthetic data as production training

### What DIODESHIELD DOES Do

- ✅ Ingests metadata-only traffic events
- ✅ Extracts bounded features (schema-validated)
- ✅ Runs models (fallback or trained)
- ✅ Scores with evidence-based fusion
- ✅ Verifies datasets with SHA-256 checksums
- ✅ Enforces reproducible temporal/group splits
- ✅ Calibrates with Platt scaling
- ✅ Records full provenance & metrics
- ✅ Writes tamper-evident hash chains

## Next Steps for Production

1. **Procure Verified Dataset**
   - Choose: UNSW-NB15, NSL-KDD, CICIDS2018, or custom labeled dataset
   - Obtain source URL, license, checksum
   - Document temporal/group provenance

2. **Configure Dataset Manifest**
   ```json
   {
     "name": "...",
     "source_url": "https://...",
     "license": "CC-BY-4.0",
     "sha256": "...",
     "label_column": "attack",
     "timestamp_column": "timestamp",
     "feature_columns": [...]
   }
   ```

3. **Run Production Training**
   ```bash
   python training/train_all_models.py --download
   ```

4. **Validate Artifacts**
   - Check metrics in `reports/production_training_report.json`
   - Verify integrity hashes
   - Confirm provenance is recorded

5. **Deploy to Production**
   - Copy trained model artifacts to production environment
   - Load artifacts at runtime: `adapter.load(artifact_path)`
   - Monitor model health via dashboard
   - Log predictions and confidence for feedback loop

## Architecture

```
DIODESHIELD Pipeline
├── Ingestion (Zeek, TShark, synthetic)
├── Streaming Window (metadata only)
├── Feature Extraction (schema-validated)
├── Model Inference (5 adapters, fallback-ready)
│   ├── XGBoost (tabular)
│   ├── LSTM (sequence)
│   ├── FFT (signal)
│   ├── Kitsune (adapted, online-learning)
│   └── Isolation Forest (ensemble)
├── Score Fusion (weighted average)
├── Risk Engine (thresholding, persistence)
├── Evidence Chain (SHA-256 tamper detection)
└── SQLite Database + Dashboard REST API
```

## References

- `training/DATASET_CONTRACT.md` - Dataset contract requirements
- `training/production.py` - Production training implementation
- `training/collect_training_data.py` - Threat scenario collection
- `diodeshield/models/adapters.py` - Model implementations
- `tests/validate_all.py` - Comprehensive validation suite
