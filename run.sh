#!/bin/bash
# Load .env and run watchtower

set -a
source .env
set +a

cargo run
