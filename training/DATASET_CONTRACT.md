# Production dataset contract

`python training/train_all_models.py` is a production-training command, not a
synthetic demo. It will **fail closed** until all of these fields are supplied
in `training/dataset_manifest.json`:

* a directly downloadable public `source_url`;
* a reviewed open license (`CC0`, `CC-BY`, Apache-2.0, BSD, ODC, or public
  domain);
* a 64-character SHA-256 checksum for the exact downloaded file;
* a binary `label_column`;
* numeric `feature_columns`; and
* either `timestamp_column` (temporal split) or `group_column` (group-aware
  split).

The manifest also records citation and provenance. Local files without a
matching checksum are rejected. Downloads are opt-in (`--download`) and use
urllib only; the workflow never generates or sends traffic. Rows are checked
for finite values, both classes, and sufficient size before a train /
calibration / test split is made.

The checked-in `data/uploaded/embedded_system_network_security_dataset.csv` has
no verified source, license, checksum, timestamp, or group provenance. It is
therefore **not production data** and is intentionally not trained. Do not
relabel it or the synthetic report as production evidence.

