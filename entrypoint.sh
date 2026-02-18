#!/bin/bash
set -e

# GitHub Action Entrypoint for CBOM Analyser
# Arguments:
#   $1 - fail-on-vulnerable (true/false)
#   $2 - output-format (json/sarif/summary)
#   $3 - output-file path
#   $4 - quantum-safe-threshold (0-100)
#   $5 - scan-path (path within repo to scan)

FAIL_ON_VULNERABLE="${1:-false}"
OUTPUT_FORMAT="${2:-summary}"
OUTPUT_FILE="${3:-cbom-report.json}"
THRESHOLD="${4:-0}"
SCAN_PATH="${5:-.}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo ""
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║     🔐 CBOM Analyser - Quantum Readiness Scanner            ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Resolve scan path
FULL_SCAN_PATH="${GITHUB_WORKSPACE}/${SCAN_PATH}"
if [ ! -d "$FULL_SCAN_PATH" ]; then
  echo -e "${RED}Error: Scan path does not exist: ${FULL_SCAN_PATH}${NC}"
  exit 1
fi

echo -e "${BLUE}📂 Scanning: ${FULL_SCAN_PATH}${NC}"
echo -e "${BLUE}📊 Output format: ${OUTPUT_FORMAT}${NC}"
echo -e "${BLUE}📄 Output file: ${OUTPUT_FILE}${NC}"
echo ""

# Start the backend server in background
cd /app
node dist/index.js &
SERVER_PID=$!

# Wait for server to be ready
echo -e "${YELLOW}Starting CBOM scanner service...${NC}"
for i in {1..30}; do
  if curl -s http://localhost:3001/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Scanner service ready${NC}"
    break
  fi
  if [ $i -eq 30 ]; then
    echo -e "${RED}Error: Scanner service failed to start${NC}"
    exit 1
  fi
  sleep 1
done

# Run the scan
echo ""
echo -e "${YELLOW}🔍 Scanning for cryptographic assets...${NC}"
echo ""

SCAN_RESULT=$(curl -s -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d "{\"repoPath\": \"${FULL_SCAN_PATH}\"}")

# Stop the server
kill $SERVER_PID 2>/dev/null || true

# Parse results
SUCCESS=$(echo "$SCAN_RESULT" | jq -r '.success')
if [ "$SUCCESS" != "true" ]; then
  echo -e "${RED}Error: Scan failed${NC}"
  echo "$SCAN_RESULT" | jq -r '.error // "Unknown error"'
  exit 1
fi

# Extract metrics
TOTAL_ASSETS=$(echo "$SCAN_RESULT" | jq '.cbom.cryptoAssets | length')
READINESS_SCORE=$(echo "$SCAN_RESULT" | jq -r '.readinessScore.score')
VULNERABLE_ASSETS=$(echo "$SCAN_RESULT" | jq '[.cbom.cryptoAssets[] | select(.quantumSafety == "vulnerable" or .quantumSafety == "unknown")] | length')
QUANTUM_SAFE_ASSETS=$(echo "$SCAN_RESULT" | jq '[.cbom.cryptoAssets[] | select(.quantumSafety == "safe")] | length')

# Always generate cbom.json for artifact download
CBOM_JSON_PATH="${GITHUB_WORKSPACE}/cbom.json"
echo "$SCAN_RESULT" | jq '.cbom' > "$CBOM_JSON_PATH"
echo -e "${GREEN}✓ Generated: cbom.json${NC}"

# Save output based on format
OUTPUT_PATH="${GITHUB_WORKSPACE}/${OUTPUT_FILE}"
case "$OUTPUT_FORMAT" in
  json)
    # If output file is different from cbom.json, also save there
    if [ "$OUTPUT_FILE" != "cbom.json" ]; then
      echo "$SCAN_RESULT" | jq '.cbom' > "$OUTPUT_PATH"
    fi
    ;;
  sarif)
    # Convert to SARIF format for GitHub Security tab
    cat > "$OUTPUT_PATH" << EOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CBOM Analyser",
          "version": "1.0.0",
          "informationUri": "https://github.com/test-srm-digi/cbom-analyser",
          "rules": [
            {
              "id": "CBOM001",
              "name": "NonQuantumSafeCrypto",
              "shortDescription": {
                "text": "Non-quantum-safe cryptographic algorithm detected"
              },
              "fullDescription": {
                "text": "This cryptographic algorithm is vulnerable to quantum computing attacks. Consider migrating to a NIST-approved post-quantum cryptographic algorithm."
              },
              "defaultConfiguration": {
                "level": "warning"
              },
              "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography"
            }
          ]
        }
      },
      "results": $(echo "$SCAN_RESULT" | jq '[.cbom.cryptoAssets[] | select(.quantumSafety == "vulnerable" or .quantumSafety == "unknown") | {
        "ruleId": "CBOM001",
        "level": (if .quantumSafety == "vulnerable" then "warning" else "note" end),
        "message": {
          "text": ("Non-quantum-safe algorithm: " + .name + " (" + (.primitive // "unknown") + ")" + (if .recommendedPQC then " - Recommended: " + .recommendedPQC else "" end))
        },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": .location.fileName
            },
            "region": {
              "startLine": (.location.lineNumber // 1)
            }
          }
        }]
      }]')
    }
  ]
}
EOF
    ;;
  summary|*)
    echo "$SCAN_RESULT" | jq '.cbom' > "$OUTPUT_PATH"
    ;;
esac

# Print summary
echo ""
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${PURPLE}                    📊 SCAN RESULTS                             ${NC}"
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Readiness score with color coding
if [ "$READINESS_SCORE" -ge 80 ]; then
  SCORE_COLOR=$GREEN
elif [ "$READINESS_SCORE" -ge 50 ]; then
  SCORE_COLOR=$YELLOW
else
  SCORE_COLOR=$RED
fi

echo -e "  🎯 Quantum Readiness Score: ${SCORE_COLOR}${READINESS_SCORE}%${NC}"
echo ""
echo -e "  📦 Total Assets:            ${BLUE}${TOTAL_ASSETS}${NC}"
echo -e "  ✅ Quantum-Safe:            ${GREEN}${QUANTUM_SAFE_ASSETS}${NC}"
echo -e "  ⚠️  Vulnerable:              ${RED}${VULNERABLE_ASSETS}${NC}"
echo ""

# Show vulnerable assets
if [ "$VULNERABLE_ASSETS" -gt 0 ]; then
  echo -e "${YELLOW}Non-quantum-safe algorithms found:${NC}"
  echo ""
  echo "$SCAN_RESULT" | jq -r '.cbom.cryptoAssets[] | select(.quantumSafety == "vulnerable" or .quantumSafety == "unknown") | "  ⚠️  \(.name) (\(.primitive // "unknown")) - \(.location.fileName):\(.location.lineNumber // "?")"'
  echo ""
fi

echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Set GitHub Action outputs
echo "readiness-score=${READINESS_SCORE}" >> $GITHUB_OUTPUT
echo "total-assets=${TOTAL_ASSETS}" >> $GITHUB_OUTPUT
echo "vulnerable-assets=${VULNERABLE_ASSETS}" >> $GITHUB_OUTPUT
echo "quantum-safe-assets=${QUANTUM_SAFE_ASSETS}" >> $GITHUB_OUTPUT
echo "cbom-file=${OUTPUT_FILE}" >> $GITHUB_OUTPUT
echo "cbom-json-file=cbom.json" >> $GITHUB_OUTPUT

# Create job summary
cat >> $GITHUB_STEP_SUMMARY << EOF
## 🔐 CBOM Analyser - Quantum Readiness Report

| Metric | Value |
|--------|-------|
| 🎯 Quantum Readiness Score | **${READINESS_SCORE}%** |
| 📦 Total Cryptographic Assets | ${TOTAL_ASSETS} |
| ✅ Quantum-Safe | ${QUANTUM_SAFE_ASSETS} |
| ⚠️ Vulnerable | ${VULNERABLE_ASSETS} |

EOF

if [ "$VULNERABLE_ASSETS" -gt 0 ]; then
  cat >> $GITHUB_STEP_SUMMARY << EOF
### ⚠️ Non-Quantum-Safe Algorithms Detected

| Algorithm | Primitive | Location |
|-----------|-----------|----------|
$(echo "$SCAN_RESULT" | jq -r '.cbom.cryptoAssets[] | select(.quantumSafety == "vulnerable" or .quantumSafety == "unknown") | "| \(.name) | \(.primitive // "unknown") | \(.location.fileName):\(.location.lineNumber // "?") |"')

> 💡 **Recommendation**: Migrate to NIST-approved post-quantum cryptographic algorithms (ML-KEM, ML-DSA, SLH-DSA)

EOF
fi

cat >> $GITHUB_STEP_SUMMARY << EOF

---
*Generated by [CBOM Analyser](https://github.com/test-srm-digi/cbom-analyser)*
EOF

# Check threshold
if [ "$READINESS_SCORE" -lt "$THRESHOLD" ]; then
  echo -e "${RED}❌ Quantum readiness score (${READINESS_SCORE}%) is below threshold (${THRESHOLD}%)${NC}"
  exit 1
fi

# Fail if vulnerable and flag is set
if [ "$FAIL_ON_VULNERABLE" = "true" ] && [ "$VULNERABLE_ASSETS" -gt 0 ]; then
  echo -e "${RED}❌ Workflow failed: ${VULNERABLE_ASSETS} non-quantum-safe cryptographic asset(s) detected${NC}"
  echo -e "${YELLOW}💡 Set 'fail-on-vulnerable: false' to allow vulnerable assets${NC}"
  exit 1
fi

echo -e "${GREEN}✓ CBOM scan completed successfully${NC}"
exit 0
