# Air-Piledriver

**Air-Piledriver** — Precision-engineered WPA2-Enterprise credential spraying and dictionary attack framework with built-in stealth, stateful resume, and full EAP customization.

---

## Core Capabilities
- Perform **online credential spraying** and **dictionary attacks** against WPA2-Enterprise networks via `wpa_supplicant`.
- Supports **multiple EAP types** (PEAP, EAP-TLS, TTLS, etc.) and advanced parameters:
  - `phase2`
  - `anonymous-identity`
  - CA certificates
  - domain/subject matching
- Target specific APs with **BSSID pinning** and optional **frequency locking**.

---

## Speed, Stealth & Reliability
- **Jittered delays** and **spray modes** (`user-first` / `pass-first`) to evade detection.
- Optional **MAC address randomization** (`off`, `once`, `each-user`, `each-pass`).
- **Exponential backoff** and cooldowns to reduce account lockouts.
- Event-driven connection monitoring with **reliable cleanup** of networks.

---

## Wordlist Handling
- Large wordlist support via **streamed reading** (no full RAM load).
- **Shuffle** users/passwords with deterministic seeds for reproducible attacks.
- Resume from **saved state** with shuffle-safe seeds and list digests.
- Optional **stdin** input for dynamic password sources.

---

## Output & Logging
- Save valid credentials to **CSV** (0600 perms) or **JSONL** for automation.
- **Structured logging** with adjustable verbosity.
- Progress tracking and optional **verbose trace** mode.

---

## Safety & Resilience
- **File-locked state saves** to prevent corruption in multi-instance runs.
- Optional **privilege drop** after D-Bus connection.
- Graceful **Ctrl+C / SIGTERM handling** with automatic checkpoint saves.
- Compatible with **Kali/Debian** and minimal installs.
