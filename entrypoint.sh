#!/bin/bash
set -e

# GitHub Action Entrypoint for CBOM Analyser
# Arguments:
#   $1 - fail-on-vulnerable (true/false)
#   $2 - output-format (json/sarif/summary)
#   $3 - output-file path
#   $4 - quantum-safe-threshold (0-100)
#   $5 - scan-path (path within repo to scan)
#   $6 - exclude-patterns (comma-separated glob patterns)

FAIL_ON_VULNERABLE="${1:-false}"
OUTPUT_FORMAT="${2:-summary}"
OUTPUT_FILE="${3:-cbom-report.json}"
THRESHOLD="${4:-0}"
SCAN_PATH="${5:-.}"
EXCLUDE_PATTERNS="${6:-}"

# Default test file patterns
DEFAULT_EXCLUDE_PATTERNS='**/test/**,**/tests/**,**/__tests__/**,**/*.test.ts,**/*.test.js,**/*.test.tsx,**/*.test.jsx,**/*.spec.ts,**/*.spec.js,**/*.spec.tsx,**/*.spec.jsx,**/Test.java,**/*Test.java,**/*Tests.java,**/test_*.py,**/*_test.py'

# If "default" is specified, use default exclusions
if [ "$EXCLUDE_PATTERNS" = "default" ]; then
  EXCLUDE_PATTERNS="$DEFAULT_EXCLUDE_PATTERNS"
fi

# External tool configuration (from env vars set by action.yml)
ENABLE_CODEQL="${ENABLE_CODEQL:-true}"
ENABLE_CBOMKIT_THEIA="${ENABLE_CBOMKIT_THEIA:-true}"
ENABLE_CRYPTO_ANALYSIS="${ENABLE_CRYPTO_ANALYSIS:-true}"
CODEQL_LANGUAGE="${CODEQL_LANGUAGE:-java}"

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
if [ -n "$EXCLUDE_PATTERNS" ]; then
  echo -e "${BLUE}🚫 Excluding: ${EXCLUDE_PATTERNS}${NC}"
fi
if [ -n "$SONAR_HOST_URL" ] && [ -n "$SONAR_TOKEN" ]; then
  echo -e "${BLUE}🔬 SonarQube: ${SONAR_HOST_URL} (sonar-cryptography enabled)${NC}"
else
  echo -e "${BLUE}🔬 Scanner: regex (set sonar-host-url + sonar-token to enable sonar-cryptography)${NC}"
fi

# Display external tool configuration
echo -e "${BLUE}🛠  External Tools:${NC}"
[ "$ENABLE_CODEQL" = "true" ] && echo -e "${BLUE}    CodeQL: enabled (language: ${CODEQL_LANGUAGE})${NC}" || echo -e "${BLUE}    CodeQL: disabled${NC}"
[ "$ENABLE_CBOMKIT_THEIA" = "true" ] && echo -e "${BLUE}    cbomkit-theia: enabled${NC}" || echo -e "${BLUE}    cbomkit-theia: disabled${NC}"
[ "$ENABLE_CRYPTO_ANALYSIS" = "true" ] && echo -e "${BLUE}    CryptoAnalysis: enabled${NC}" || echo -e "${BLUE}    CryptoAnalysis: disabled${NC}"
echo ""

# ── Install external analysis tools (runtime download, before server start) ──
TOOLS_DIR="/opt/cbom-tools"
mkdir -p "$TOOLS_DIR"

# CodeQL CLI (glibc binary — gcompat must be installed in Dockerfile)
if [ "$ENABLE_CODEQL" = "true" ] && ! command -v codeql &>/dev/null; then
  # Download the official CodeQL BUNDLE (CLI + all standard QL packs).
  # The CLI-only download from github/codeql-cli-binaries does NOT include
  # the standard packs (codeql/java-all, etc.), causing analysis to fail.
  # See: https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli
  CODEQL_VERSION="v2.24.2"
  echo -e "${YELLOW}⬇  Downloading CodeQL bundle ${CODEQL_VERSION} (CLI + QL packs)...${NC}"
  BUNDLE_URL="https://github.com/github/codeql-action/releases/download/codeql-bundle-${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"
  if curl -fsSL "$BUNDLE_URL" -o /tmp/codeql-bundle.tar.gz 2>/dev/null; then
    tar -xzf /tmp/codeql-bundle.tar.gz -C "$TOOLS_DIR" 2>/dev/null
    if [ -x "$TOOLS_DIR/codeql/codeql" ]; then
      # Add to PATH instead of symlinking.  When invoked via a symlink at
      # /usr/local/bin/codeql the binary resolves its location as /usr/local/bin/
      # and fails to find the bundled qlpacks/ directory next to it.
      export PATH="$TOOLS_DIR/codeql:$PATH"
      echo -e "${GREEN}   ✓ CodeQL bundle ${CODEQL_VERSION} installed${NC}"
      # Verify bundled packs are present
      if [ -d "$TOOLS_DIR/codeql/qlpacks/codeql/java-all" ]; then
        echo -e "${GREEN}   ✓ Bundled QL packs verified (codeql/java-all present)${NC}"
      else
        echo -e "${YELLOW}   ⚠ Bundled QL packs not found at expected location${NC}"
      fi
    else
      echo -e "${YELLOW}   ⚠ CodeQL extraction failed (non-blocking)${NC}"
    fi
    rm -f /tmp/codeql-bundle.tar.gz
  else
    echo -e "${YELLOW}   ⚠ CodeQL bundle download failed (non-blocking)${NC}"
  fi
fi

# cbomkit-theia (Go project — no pre-built binaries, requires Go toolchain)
if [ "$ENABLE_CBOMKIT_THEIA" = "true" ] && ! command -v cbomkit-theia &>/dev/null && ! command -v cbomkit &>/dev/null; then
  if command -v go &>/dev/null; then
    echo -e "${YELLOW}⬇  Building cbomkit-theia from source (Go)...${NC}"
    if GOBIN="$TOOLS_DIR" go install github.com/cbomkit/cbomkit-theia@latest 2>/dev/null; then
      ln -sf "$TOOLS_DIR/cbomkit-theia" /usr/local/bin/cbomkit-theia
      echo -e "${GREEN}   ✓ cbomkit-theia built and installed${NC}"
    else
      echo -e "${YELLOW}   ⚠ cbomkit-theia build failed (non-blocking)${NC}"
    fi
  else
    echo -e "${YELLOW}   ⚠ cbomkit-theia: no pre-built binaries available — requires Go toolchain (non-blocking)${NC}"
  fi
fi

# CryptoAnalysis (HeadlessJavaScanner — Java JAR, uses already-installed JRE)
if [ "$ENABLE_CRYPTO_ANALYSIS" = "true" ] && ! command -v CryptoAnalysis &>/dev/null; then
  echo -e "${YELLOW}⬇  Downloading CryptoAnalysis (HeadlessJavaScanner)...${NC}"
  CRYPTO_ANALYSIS_VERSION="5.0.1"
  JAR_URL="https://github.com/CROSSINGTUD/CryptoAnalysis/releases/download/${CRYPTO_ANALYSIS_VERSION}/HeadlessJavaScanner-${CRYPTO_ANALYSIS_VERSION}-jar-with-dependencies.jar"
  RULES_URL="https://github.com/CROSSINGTUD/CryptoAnalysis/releases/download/${CRYPTO_ANALYSIS_VERSION}/JavaCryptographicArchitecture.zip"
  if curl -fsSL "$JAR_URL" -o "$TOOLS_DIR/HeadlessJavaScanner.jar" 2>/dev/null; then
    # Also download CrySL rules for JCA
    if curl -fsSL "$RULES_URL" -o /tmp/jca-rules.zip 2>/dev/null; then
      mkdir -p "$TOOLS_DIR/crysl-rules"
      unzip -qo /tmp/jca-rules.zip -d "$TOOLS_DIR/crysl-rules" 2>/dev/null
      rm -f /tmp/jca-rules.zip
      echo -e "${GREEN}   ✓ CrySL rules downloaded${NC}"
    fi
    cat > /usr/local/bin/CryptoAnalysis << 'WRAPPER'
#!/bin/bash
exec java -jar /opt/cbom-tools/HeadlessJavaScanner.jar "$@"
WRAPPER
    chmod +x /usr/local/bin/CryptoAnalysis
    echo -e "${GREEN}   ✓ CryptoAnalysis (HeadlessJavaScanner) v${CRYPTO_ANALYSIS_VERSION} installed${NC}"
  else
    echo -e "${YELLOW}   ⚠ CryptoAnalysis download failed (non-blocking)${NC}"
  fi
fi

echo ""

# ── Try to compile Java project for deeper analysis (CodeQL + CryptoAnalysis) ──
JAVA_BUILD_SUCCESS=false
if [ -f "$FULL_SCAN_PATH/pom.xml" ] || [ -f "$FULL_SCAN_PATH/build.gradle" ] || [ -f "$FULL_SCAN_PATH/build.gradle.kts" ]; then
  echo -e "${YELLOW}📦 Java project detected — attempting compilation for deep analysis...${NC}"
  if [ -f "$FULL_SCAN_PATH/mvnw" ]; then
    chmod +x "$FULL_SCAN_PATH/mvnw" 2>/dev/null
    if COMPILE_OUT=$(cd "$FULL_SCAN_PATH" && ./mvnw compile -DskipTests -B 2>&1); then
      JAVA_BUILD_SUCCESS=true
    else
      echo "   Maven compile error (last 5 lines):"
      echo "$COMPILE_OUT" | tail -5 | sed 's/^/   /'
    fi
  elif [ -f "$FULL_SCAN_PATH/gradlew" ]; then
    chmod +x "$FULL_SCAN_PATH/gradlew" 2>/dev/null
    if COMPILE_OUT=$(cd "$FULL_SCAN_PATH" && ./gradlew compileJava --no-daemon 2>&1); then
      JAVA_BUILD_SUCCESS=true
    else
      echo "   Gradle compile error (last 5 lines):"
      echo "$COMPILE_OUT" | tail -5 | sed 's/^/   /'
    fi
  elif command -v mvn &>/dev/null && [ -f "$FULL_SCAN_PATH/pom.xml" ]; then
    if COMPILE_OUT=$(cd "$FULL_SCAN_PATH" && mvn compile -DskipTests -B 2>&1); then
      JAVA_BUILD_SUCCESS=true
    else
      echo "   Maven compile error (last 5 lines):"
      echo "$COMPILE_OUT" | tail -5 | sed 's/^/   /'
    fi
  fi

  if [ "$JAVA_BUILD_SUCCESS" = "true" ]; then
    echo -e "${GREEN}   ✓ Java project compiled — CodeQL and CryptoAnalysis will use compiled classes${NC}"
  else
    echo -e "${YELLOW}   ⚠ Java compilation skipped/failed — CodeQL will use source-only mode${NC}"
  fi
  echo ""
fi

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

# Derive repository URL and branch from standard GitHub Actions env vars
REPO_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}"
BRANCH="${GITHUB_REF_NAME}"

# Build the request JSON with optional excludePatterns + repo metadata + external tools
EXTERNAL_TOOLS=$(jq -n \
  --argjson codeql "$([ "$ENABLE_CODEQL" = "true" ] && echo true || echo false)" \
  --argjson cbomkit "$([ "$ENABLE_CBOMKIT_THEIA" = "true" ] && echo true || echo false)" \
  --argjson crypto "$([ "$ENABLE_CRYPTO_ANALYSIS" = "true" ] && echo true || echo false)" \
  --arg lang "$CODEQL_LANGUAGE" \
  '{enableCodeQL: $codeql, enableCbomkitTheia: $cbomkit, enableCryptoAnalysis: $crypto, codeqlLanguage: $lang}')

if [ -n "$EXCLUDE_PATTERNS" ]; then
  # Convert comma-separated patterns to JSON array
  EXCLUDE_JSON=$(echo "$EXCLUDE_PATTERNS" | tr ',' '\n' | jq -R . | jq -s .)
  REQUEST_BODY=$(jq -n \
    --arg path "$FULL_SCAN_PATH" \
    --argjson exclude "$EXCLUDE_JSON" \
    --arg repoUrl "$REPO_URL" \
    --arg branch "$BRANCH" \
    --argjson externalTools "$EXTERNAL_TOOLS" \
    '{repoPath: $path, excludePatterns: $exclude, repoUrl: $repoUrl, branch: $branch, externalTools: $externalTools}')
else
  REQUEST_BODY=$(jq -n \
    --arg path "$FULL_SCAN_PATH" \
    --arg repoUrl "$REPO_URL" \
    --arg branch "$BRANCH" \
    --argjson externalTools "$EXTERNAL_TOOLS" \
    '{repoPath: $path, repoUrl: $repoUrl, branch: $branch, externalTools: $externalTools}')
fi

SCAN_RESULT=$(curl -s -X POST http://localhost:3001/api/scan-code/full \
  -H "Content-Type: application/json" \
  -d "$REQUEST_BODY")

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
VULNERABLE_ASSETS=$(echo "$SCAN_RESULT" | jq '[.cbom.cryptoAssets[] | select(.quantumSafety == "not-quantum-safe" or .quantumSafety == "unknown")] | length')
QUANTUM_SAFE_ASSETS=$(echo "$SCAN_RESULT" | jq '[.cbom.cryptoAssets[] | select(.quantumSafety == "quantum-safe")] | length')

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
      "results": $(echo "$SCAN_RESULT" | jq '[.cbom.cryptoAssets[] | select(.quantumSafety == "not-quantum-safe" or .quantumSafety == "unknown") | {
        "ruleId": "CBOM001",
        "level": (if .quantumSafety == "not-quantum-safe" then "warning" else "note" end),
        "message": {
          "text": ("Non-quantum-safe algorithm: " + .name + " (" + (.cryptoProperties.algorithmProperties.primitive // "unknown") + ")" + (if .pqcRecommendation then " - Recommended: " + .pqcRecommendation else "" end))
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
  echo "$SCAN_RESULT" | jq -r '.cbom.cryptoAssets[] | select(.quantumSafety == "not-quantum-safe" or .quantumSafety == "unknown") | "  ⚠️  \(.name) (\(.cryptoProperties.algorithmProperties.primitive // "unknown")) - \(.location.fileName):\(.location.lineNumber // "?")"'
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
| 🔗 Repository | [${GITHUB_REPOSITORY}](${REPO_URL}) |
| 🌿 Branch | \`${BRANCH}\` |

EOF

if [ "$VULNERABLE_ASSETS" -gt 0 ]; then
  cat >> $GITHUB_STEP_SUMMARY << EOF
### ⚠️ Non-Quantum-Safe Algorithms Detected

| Algorithm | Primitive | Location |
|-----------|-----------|----------|
$(echo "$SCAN_RESULT" | jq -r '.cbom.cryptoAssets[] | select(.quantumSafety == "not-quantum-safe" or .quantumSafety == "unknown") | "| \(.name) | \(.cryptoProperties.algorithmProperties.primitive // "unknown") | \(.location.fileName):\(.location.lineNumber // "?") |"')

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
