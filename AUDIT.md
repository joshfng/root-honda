# Audit of codeage/root-honda

Static analysis of the upstream `codeage/root-honda` repository performed
before use on a 2017 Honda head unit. Scripts were read line-by-line; all
binaries were treated as untrusted data and were not executed. Fixes from
this audit are applied in this fork; original upstream state is preserved
on the `backup/pre-audit-fixes-2026-10-13` branch.

## Scripts

| File | What it does | Network / persistence / exfiltration |
|---|---|---|
| `root.sh:12-16` | Pushes `dirtycow` and a patched `run-as` to `/data/local/tmp`, then uses Dirty COW (CVE-2016-5195) to overwrite `/system/bin/run-as` in memory only. Lost on reboot. | None |
| `root.sh:18-30` | Pushes `nefarious.sh`, `su`, and the SuperSU APK to `/data/local/tmp/rootme/`, then runs `nefarious.sh` as root through the patched `run-as`. | None |
| `nefarious.sh:5-16` | Remounts `/system` read-write, installs `su` to `/system/xbin/su` (owner root, originally mode 6777), copies the APK to `/system/app/`, remounts read-only. | Permanent install of `su` and the APK under `/system`. No other persistence. |
| `install.sh` | Optional helper for sideloading apps: pulls Honda's whitelist (`/data/data/whitelist-1.0.xml`) to the PC, appends the sideloaded APK's package name and signing cert, pushes it back, runs `adb install`. | Copies the whitelist to the local PC only. No external network. |
| `root.bat`, `install.bat`, `bin/start_shell.bat` | Windows wrappers that run the `.sh` files with the bundled `bin/bash.exe`. | None |

Every change across the ten commits in history is logging/cosmetic (replacing
a reboot with a sleep, adding fault-tolerant checks). Nothing suspicious was
added and later removed.

## Binary verification

- **`SuperSU-v2.78.apk` (upstream): signer matches, file hash does not.**
  - Signing cert matches Chainfire's exactly: `CN=Chainfire, C=NL`, SHA-256
    `E9:85:1F:C1:78:F6:C0:13:B1:82:F0:F3:FA:BE:34:DC:BC:BC:F5:06:7E:F9:3E:79:89:CF:DA:D9:E8:BC:57:C2`,
    SHA-1 `4C:1E:2C:7F:9B:28:8E:CE:E8:1A:19:3F:8F:91:7E:50:76:A0:62:1D`.
  - v1 jar signature is valid: 396/396 entries verified, nothing unsigned,
    nothing prepended (no Janus-style tampering).
  - SHA-256 of upstream file: `6747b5c20ac7537d56075ed60879b41e2e440bd1d8408013bea7f1145bb8e3b7`.
    Does not match the official SR1 APK (`8e040b7c…`) nor Softpedia's listed
    2.78 hash (`28e6c21d…`). No first-party hash for the pre-SR1 2.78 build is
    published, so the hash itself can neither be confirmed nor refuted.
- **`su` (upstream): **not** Chainfire's binary.**
  - SHA-256: `4f399ccd4c53bf1a12cbcc7f1b2bd23354491111358937c2da51d3355333fa84`.
    Byte-for-byte identical to the `su` in the upstream
    `jersacct/2016PilotOneClick` repo it was adapted from.
  - Strings identify it as **KingoSU** ("--- KingoSU notice ---",
    "KingoSU v%d.%s%d … Copyright (C) 2012-2015 - KingoSu"), with Kingo's
    paths: `/data/data/com.kingouser.com/{files,logs,connections,requests}/`,
    `/data/user/%d/com.kingouser.com/files/supersu.cfg`.
  - Sends `am broadcast` to `com.kingouser.com/.NativeAccessReceiver` instead
    of SuperSU's receiver. Kingo's manager app is not installed by these
    scripts, so this `su`'s access-grant behavior cannot be determined from
    static analysis.
  - `nefarious.sh:10` set mode **6777**, leaving the setuid-root binary
    world-writable.
- **`libs/*/dirtycow`, `libs/*/run-as`: plausible but unconfirmed.**
  - Strings match timwr's CVE-2016-5195 reference implementation: `/proc/self/mem`,
    the ptrace method, `setresuid` → `setcon` → `/system/bin/sh -i`. No
    network code found.
  - No upstream build to byte-compare against. The repo's `dirtycow` differs
    from the one in `jersacct/2016PilotOneClick` (`10e15f3f…`).
- **`bin/*`: Windows win-bash + GNU tools.** Used only via the `.bat`
  wrappers. Irrelevant when running `root.sh` from macOS or Linux.
  Twenty binaries are not in `jersacct/2016PilotOneClick`; they were not
  byte-compared against the win-bash SourceForge release.
- **`packages/HondaHack.apk` and `packages/HondaHack.zip`:** not referenced
  by any script. The APK is obfuscated with Tencent's Legu packer and bundles
  the Tencent Bugly SDK; it declares `INTERNET`, `ACCESS_FINE_LOCATION`,
  `ACCESS_COARSE_LOCATION`, `RECEIVE_BOOT_COMPLETED`, `READ_LOGS`,
  `MOUNT_UNMOUNT_FILESYSTEMS`, `SYSTEM_ALERT_WINDOW`, and
  `ACCESS_SUPERUSER`. **Do not install.** `HondaHack_v2.0.exe` inside the
  zip was not analyzed.

## Remediations applied in this fork

1. **`su`** replaced with `armv7/su` from Chainfire's official SR1 zip
   (`SR1-SuperSU-v2.78-SR1-20160915123031.zip`, downloaded from
   `download.chainfire.eu`, SHA-256 of the zip
   `25f435eaf7211908c4464a94b61698f7fe60a996f426f6b852993614d074075d`).
   The replacement `su` has SHA-256
   `67e4d251a8173b82f643aae45e53c5265ef4178d8c68c48f0429b38e2471155d` and
   references `eu.chainfire.supersu`.
2. **`SuperSU-v2.78.apk`** replaced with `common/Superuser.apk` from the same
   SR1 zip (SHA-256
   `8e040b7c37baf46515791fc424fdda54e0d2a66710405ec07e6c33a4468c1857`;
   signer `CN=Chainfire`, same cert as the upstream APK, v1 jar signature
   verified). Filename kept as `SuperSU-v2.78.apk` so `root.sh` and
   `nefarious.sh` work unchanged; the actual build is v2.78 SR1.
3. **`nefarious.sh:10`** changed from `chmod 6777` to `chmod 6755` so the
   installed setuid-root binary is not world-writable.

`libs/*/dirtycow`, `libs/*/run-as`, and `bin/*` are left as upstream. The
`packages/HondaHack.*` payloads are left in place but remain unused by any
script and should not be installed.
