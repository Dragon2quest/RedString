#!/bin/bash
cd "$(dirname "$0")"
python3 -m unittest enterprise_telemetry/test_suite.py
