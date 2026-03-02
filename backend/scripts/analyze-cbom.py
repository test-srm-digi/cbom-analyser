#!/usr/bin/env python3
"""Analyze a CBOM JSON file for false positives and suspicious detections.
Handles both CycloneDX components[] format (IBM Sonar) and our cryptoAssets[] format."""
import json, sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "cbom-output.json"
with open(path) as f:
    d = json.load(f)

# Detect format
if d.get("cryptoAssets"):
    raw = d["cryptoAssets"]
    fmt = "cbom-analyser"
else:
    raw = d.get("components", [])
    fmt = "CycloneDX"

print(f"File: {path}")
print(f"Format: {fmt}")
print(f"Total assets: {len(raw)}\n")

# Normalize
assets = []
for c in raw:
    if fmt == "cbom-analyser":
        a = {
            "name": c.get("name", ""),
            "type": c.get("cryptoProperties", {}).get("assetType", ""),
            "primitive": c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive", ""),
            "cf": c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("cryptoFunctions", []),
            "file": c.get("location", {}).get("fileName", ""),
            "line": c.get("location", {}).get("lineNumber", ""),
            "safety": c.get("quantumSafety", ""),
            "desc": c.get("description", "") or "",
        }
    else:
        ev = c.get("evidence", {})
        occs = ev.get("occurrences", [])
        occ = occs[0] if occs else {}
        cp = c.get("cryptoProperties", {})
        ap = cp.get("algorithmProperties", {})
        a = {
            "name": c.get("name", ""),
            "type": cp.get("assetType", ""),
            "primitive": ap.get("primitive", ""),
            "cf": ap.get("cryptoFunctions", []),
            "file": occ.get("location", ""),
            "line": occ.get("line", ""),
            "safety": "",
            "desc": "",
        }
    assets.append(a)

by_name = defaultdict(list)
for a in assets:
    by_name[a["name"]].append(a)

print("=" * 100)
print(f"{'Name':35s} {'Type':15s} {'Prim':12s} {'Safety':18s} {'#':>3s}  First occurrence")
print("=" * 100)
for name in sorted(by_name.keys()):
    items = by_name[name]
    first = items[0]
    loc = f"{first['file']}:{first['line']}"
    safety = first["safety"][:18] if first["safety"] else ""
    print(f"  {name[:33]:33s} {first['type'][:15]:15s} {first['primitive'][:12]:12s} {safety:18s} {len(items):3d}  {loc}")

# FALSE POSITIVE ANALYSIS
print("\n" + "=" * 100)
print("FALSE POSITIVE / SUSPICIOUS DETECTIONS")
print("=" * 100)
fp = 0
for name, items in sorted(by_name.items()):
    reasons = []
    nl = name.lower()
    if "random" in nl and "securerandom" not in nl:
        reasons.append("Weak PRNG (not crypto) - should be flagged insecure, not as crypto asset")
    if items[0]["type"] == "algorithm" and (name.startswith("TLS") or name.startswith("SSL")):
        reasons.append("TLS/SSL version is a PROTOCOL, not an algorithm")
    if nl in ("base64", "hex", "utf-8", "utf8", "ascii", "unicode", "pem"):
        reasons.append("Encoding/format, NOT a crypto algorithm")
    if name == "MGF1":
        reasons.append("MGF1 alone is not standalone - component of RSA-OAEP")
    if name in ("PrivateKey", "PublicKey", "KeyPair", "Certificate") and items[0]["type"] == "algorithm":
        reasons.append("Generic key concept, not a specific algorithm")
    if reasons:
        fp += 1
        files = set(i["file"].split("/")[-1] if i["file"] else "?" for i in items)
        print(f"\n  ** {name} (x{len(items)}) in {', '.join(files)}")
        for r in reasons:
            print(f"     -> {r}")

if fp == 0:
    print("\n  No obvious false positives detected.")

# ALGORITHM SUMMARY (only real algos)
print("\n" + "=" * 100)
print("ALGORITHM SUMMARY (excluding related-crypto-material)")
print("=" * 100)
real = [a for a in assets if "@" not in a["name"] and a["type"] not in ("related-crypto-material",)]
real_names = sorted(set(a["name"] for a in real))
print(f"  Unique names: {len(real_names)}")
for n in real_names:
    cnt = len([a for a in real if a["name"] == n])
    sf = next((a["safety"] for a in real if a["name"] == n and a["safety"]), "")
    print(f"    {n:35s} {sf:18s} (x{cnt})")
