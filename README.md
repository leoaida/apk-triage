# apk-triage

A small, dependency-free static triage tool for Android APKs. Point it at a
sample you don't trust and it tells you the things you want to know before
spending real time on it:

- declared permissions, with the dangerous ones called out and *why* they matter
- risky API usage found inside the DEX (dynamic code loading, SMS handling,
  accessibility abuse, reflection, root checks, ...)
- embedded URLs and IPs that are worth pivoting on

Everything is static. The APK is only ever opened as a zip archive and read -
nothing is executed - so it's safe to run against malware.

## Why

When you get handed an unknown APK, the first ten minutes are always the same
boring checklist: unzip it, look at the manifest, grep the DEX for the usual
suspects, pull out any hard-coded C2. I got tired of doing that by hand, so
this does the first pass and prints a short report. It's not a replacement for
jadx / androguard / a real sandbox - it's the thing you run *before* you decide
whether the sample is worth opening in them.

## Usage

```bash
python3 apk_triage.py suspicious.apk
```

JSON output (handy for feeding into other tooling or a notebook):

```bash
python3 apk_triage.py suspicious.apk --json > report.json
```

Requires Python 3.8+. No third-party packages.

## Example

```
============================================================
apk-triage report: suspicious.apk
============================================================
MD5    : 9f2c...
SHA256 : 4ab1...
DEX    : classes.dex
Risk   : HIGH (score 12)

[ Flagged permissions ]  4
  ! SEND_SMS                     can send SMS (premium-rate fraud / OTP relay)
  ! RECEIVE_SMS                  can intercept incoming SMS (OTP theft)
  ! BIND_ACCESSIBILITY_SERVICE   accessibility abuse (auto-click / keylog)
  ! REQUEST_INSTALL_PACKAGES     can trigger APK installs (dropper behaviour)
  (+ 6 other permissions)

[ Suspicious APIs ]  3
  ! Ldalvik/system/DexClassLoader;
      runtime code loading (packed / staged payload)
  ! sendTextMessage
      sends SMS directly
  ! Landroid/accessibilityservice
      accessibility service (overlay / keylog abuse)

[ Embedded URLs ]  1
  - http://45.136.xx.xx/gate.php

[ Embedded IPs ]  1
  - 45.136.xx.xx
============================================================
```

## How it works

- **Permissions** are read straight out of `AndroidManifest.xml`. The names
  survive as plaintext in the binary manifest's string pool, so a regex over
  the raw bytes is enough for a triage pass - no AXML decoder needed.
- **APIs** are matched as substrings against each `classes*.dex`. The signature
  list in `apk_triage.py` is easy to extend; add a `(signature, note)` pair.
- **URLs / IPs** are pulled from printable strings across the DEX files.

The risk score is deliberately dumb (weighted count of flagged permissions,
API hits and IPs) - it's a sort order, not a verdict. Read the report.

## Notes / limitations

- String-level matching means reflection and heavy obfuscation can hide calls
  from it. A clean report is not a clean sample.
- It doesn't decode resources or decompile anything; use jadx for that once
  triage says the sample is interesting.

## License

MIT
