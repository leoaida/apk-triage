#!/usr/bin/env python3
"""
apk-triage - quick static triage for suspicious Android APKs.

Pulls the high-signal stuff you look at first on an unknown sample, without
running it: declared permissions, risky API usage inside the DEX, and any
embedded URLs / IPs. Everything is static - the APK is only ever read as a
zip archive - so it's safe to point at a sample you don't trust.

Usage:
    python3 apk_triage.py suspicious.apk
    python3 apk_triage.py suspicious.apk --json > report.json
"""

import argparse
import hashlib
import json
import re
import sys
import zipfile
from collections import OrderedDict

# Permissions worth a second look on an unknown sample, with why they matter.
DANGEROUS_PERMISSIONS = {
    "SEND_SMS": "can send SMS (premium-rate fraud / OTP relay)",
    "RECEIVE_SMS": "can intercept incoming SMS (OTP theft)",
    "READ_SMS": "can read stored SMS",
    "CALL_PHONE": "can place calls with no user action",
    "READ_PHONE_STATE": "reads IMEI / line number / SIM state",
    "READ_CONTACTS": "reads the address book",
    "RECORD_AUDIO": "can record from the microphone",
    "CAMERA": "can access the camera",
    "ACCESS_FINE_LOCATION": "precise location",
    "SYSTEM_ALERT_WINDOW": "draws over other apps (overlay attacks)",
    "REQUEST_INSTALL_PACKAGES": "can trigger APK installs (dropper behaviour)",
    "BIND_ACCESSIBILITY_SERVICE": "accessibility abuse (auto-click / keylog)",
    "WRITE_SETTINGS": "can change system settings",
    "RECEIVE_BOOT_COMPLETED": "auto-starts on boot (persistence)",
    "PACKAGE_USAGE_STATS": "sees which apps are being used",
    "QUERY_ALL_PACKAGES": "enumerates every installed app",
    "DISABLE_KEYGUARD": "can dismiss the lock screen",
    "GET_TASKS": "inspects running tasks",
}

# DEX type / method signatures that often show up in malicious samples. Matched
# as plain substrings against the bytes of each classes*.dex - good enough for
# triage, and it doesn't need a full DEX parser.
SUSPICIOUS_APIS = [
    ("Ldalvik/system/DexClassLoader;", "runtime code loading (packed / staged payload)"),
    ("Ldalvik/system/PathClassLoader;", "runtime class loading"),
    ("Ljava/lang/Runtime;", "may spawn shell commands (Runtime.exec)"),
    ("Ljava/lang/reflect/Method;", "reflection - often used to hide API calls"),
    ("getDeviceId", "reads IMEI"),
    ("getSubscriberId", "reads IMSI"),
    ("getSimSerialNumber", "reads SIM serial"),
    ("Landroid/telephony/SmsManager;", "SMS handling"),
    ("sendTextMessage", "sends SMS directly"),
    ("abortBroadcast", "suppresses the SMS broadcast (hides incoming texts)"),
    ("Landroid/accessibilityservice", "accessibility service (overlay / keylog abuse)"),
    ("setComponentEnabledSetting", "can hide its own launcher icon"),
    ("addJavascriptInterface", "JS<->native bridge inside a WebView"),
    ("Ljavax/crypto/Cipher;", "encryption (C2 traffic / string obfuscation)"),
    ("Landroid/util/Base64;", "base64 (encoded strings / payloads)"),
    ("/system/bin/su", "root check or root abuse"),
    ("getInstalledPackages", "enumerates installed apps"),
    ("Landroid/telephony/TelephonyManager;", "device / telephony fingerprinting"),
]

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PERM_RE = re.compile(r"android\.permission\.([A-Z_]+)")


def file_hashes(path):
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def printable_strings(data):
    return (m.group().decode("ascii", "ignore") for m in PRINTABLE_RE.finditer(data))


def read_permissions(z):
    try:
        raw = z.read("AndroidManifest.xml")
    except KeyError:
        return []
    # Permission names survive as readable entries in the binary manifest's
    # string pool. That pool can be UTF-8 or UTF-16; in the UTF-16 case the
    # characters are null-interleaved, so scan a null-stripped copy as well or
    # we'd miss every permission on those manifests.
    perms = set(PERM_RE.findall(raw.decode("latin-1")))
    perms |= set(PERM_RE.findall(raw.replace(b"\x00", b"").decode("latin-1")))
    return sorted(perms)


def looks_like_ip(ip):
    try:
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    except ValueError:
        return False


def scan_dex(z):
    api_hits = OrderedDict()
    urls, ips = set(), set()
    for name in z.namelist():
        if not name.endswith(".dex"):
            continue
        data = z.read(name)
        blob = data.decode("latin-1")
        for sig, desc in SUSPICIOUS_APIS:
            if sig in blob:
                api_hits.setdefault(sig, desc)
        for s in printable_strings(data):
            urls.update(URL_RE.findall(s))
            ips.update(ip for ip in IP_RE.findall(s) if looks_like_ip(ip))
    return api_hits, sorted(urls), sorted(ips)


def triage(path):
    with zipfile.ZipFile(path) as z:
        perms = read_permissions(z)
        api_hits, urls, ips = scan_dex(z)
        dex_files = [n for n in z.namelist() if n.endswith(".dex")]

    flagged = {p: DANGEROUS_PERMISSIONS[p] for p in perms if p in DANGEROUS_PERMISSIONS}
    md5, sha256 = file_hashes(path)
    score = 2 * len(flagged) + len(api_hits) + len(ips)

    return {
        "file": path,
        "md5": md5,
        "sha256": sha256,
        "dex_files": dex_files,
        "permissions": perms,
        "flagged_permissions": flagged,
        "suspicious_apis": [{"signature": s, "note": n} for s, n in api_hits.items()],
        "urls": urls,
        "ips": ips,
        "risk_score": score,
    }


def risk_label(score):
    if score >= 12:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def print_report(r):
    line = "=" * 60
    print(line)
    print(f"apk-triage report: {r['file']}")
    print(line)
    print(f"MD5    : {r['md5']}")
    print(f"SHA256 : {r['sha256']}")
    print(f"DEX    : {', '.join(r['dex_files']) or 'none found'}")
    print(f"Risk   : {risk_label(r['risk_score'])} (score {r['risk_score']})")

    print(f"\n[ Flagged permissions ]  {len(r['flagged_permissions'])}")
    for p, why in r["flagged_permissions"].items():
        print(f"  ! {p:<28} {why}")
    other = [p for p in r["permissions"] if p not in r["flagged_permissions"]]
    if other:
        print(f"  (+ {len(other)} other permissions)")

    print(f"\n[ Suspicious APIs ]  {len(r['suspicious_apis'])}")
    for hit in r["suspicious_apis"]:
        print(f"  ! {hit['signature']}")
        print(f"      {hit['note']}")

    print(f"\n[ Embedded URLs ]  {len(r['urls'])}")
    for u in r["urls"][:40]:
        print(f"  - {u}")
    if len(r["urls"]) > 40:
        print(f"  ... {len(r['urls']) - 40} more")

    print(f"\n[ Embedded IPs ]  {len(r['ips'])}")
    for ip in r["ips"][:40]:
        print(f"  - {ip}")
    print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Static triage for suspicious Android APKs.")
    ap.add_argument("apk", help="path to the .apk file")
    ap.add_argument("--json", action="store_true", help="emit a JSON report instead of text")
    args = ap.parse_args(argv)

    try:
        report = triage(args.apk)
    except FileNotFoundError:
        sys.exit(f"error: no such file: {args.apk}")
    except zipfile.BadZipFile:
        sys.exit(f"error: not a valid APK/zip: {args.apk}")

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print_report(report)


if __name__ == "__main__":
    main()
