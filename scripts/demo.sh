#!/usr/bin/env bash
set -euo pipefail
python producer/simulator.py --base http://localhost:8080 --count 20
