# Model card

## Training status (2026-09-09)

No production model is trained or serialized in this workspace. The checked-in
adapters are deterministic fallback/online evidence branches for passive
receive-side operation. `reports/synthetic_training_report.json` is explicitly
`synthetic_lab_evaluation` and must not be used as production performance.

## Reproducible training

`training/train_all_models.py` now requires a verified open-data manifest. The
manifest must identify a downloadable source, reviewed license, checksum,
numeric schema, and temporal or group split. The command writes artifacts only
after schema checks, calibration, threshold selection, and test metrics
(ROC-AUC, PR-AUC, precision, recall, F1, and latency) succeed. Artifact JSON
contains model version, feature schema, provenance, and integrity metadata.
See `training/DATASET_CONTRACT.md`.

The `fft` and adapted `kitsune` branches have dependency-free, streaming
calibration workflows. XGBoost, LSTM, and Isolation Forest remain explicit
optional-backend gaps until their reviewed estimator implementations and real
labeled data are available. Kitsune is `diodeshield-adapted-kitnet-fallback`;
third-party Kitsune is not bundled.

## Intended use and limitations

Inference accepts the same bounded feature dictionaries emitted by the
streaming feature builder. Model agreement is evidence, not a calibrated
probability unless a verified artifact is loaded. The system is passive: it
does not craft packets, probe assets, or block traffic automatically.
