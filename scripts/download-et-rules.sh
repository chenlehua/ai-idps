#!/bin/bash

set -euo pipefail

RULES_DIR="/var/lib/nids/rules"
ET_RULES_URL="https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"

mkdir -p "$RULES_DIR"
cd "$RULES_DIR"

curl -L -o emerging.rules.tar.gz "$ET_RULES_URL"
tar xzf emerging.rules.tar.gz

cat rules/*.rules > suricata.rules

echo "ET Open rules downloaded to $RULES_DIR/suricata.rules"
