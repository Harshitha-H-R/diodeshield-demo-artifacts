#!/usr/bin/env bash
set -euo pipefail
python -m diodeshield.cli --scenario normal --count 30
python -m diodeshield.cli --scenario recon --count 30
python -m diodeshield.cli --scenario protocol --count 30
echo "Demo complete. Start the API with: uvicorn diodeshield.api.main:app --reload"
