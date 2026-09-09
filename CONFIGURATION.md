# Configuration

`configs/default.yaml` is loaded by `DIODESHIELD_CONFIG`. Window size/slide,
enabled adapters, fusion starting weights, risk thresholds, persistence and
retention are centralized there. Fusion weights are demonstration defaults, not
validated production values. `DIODESHIELD_DB` selects the SQLite file.

Optional validated XGBoost artifacts can be enabled with
`model_artifacts.xgboost: path/to/model.json`. If XGBoost or the artifact is
unavailable, the adapter remains on the deterministic metadata-only fallback.
SHAP is likewise optional; alerts always retain deterministic evidence when a
TreeSHAP artifact cannot be loaded.

The core detector does not need external services, credentials, DNS, a reverse
path, or payload decryption. Set `security.allow_payload` only when a parser
requires protocol bytes and the collection decision has been approved.
