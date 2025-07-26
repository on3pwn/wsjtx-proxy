#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# WSJT-X UDP Proxy with rigctl Integration
# Copyright (C) 2025 YourNameOrCallsign
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

#WSJT-X UDP Proxy with rigctl Integration
#----------------------------------------
#
# Description:
#     This script acts as a UDP proxy between WSJT-X and one or more clients.
#     It captures Status and ADIF messages, enriches ADIF logs with real-time TX power
#     measurements (via rigctl), and logs QSOs into an ADIF file.
#
# Features:
#     - Forwards WSJT-X UDP traffic to multiple clients
#     - Parses and enhances ADIF entries (RST, TX power, comments)
#     - Live RF measurements using rigctl (via hamlib)
#     - FT8-compatible; extensible to other WSJT-X modes
# 
# Dependencies:
#     - Python 3.7+
#     - hamlib (required for rigctl): install via `sudo pacman -S hamlib`
#     - Uses only Python Standard Library (no pip requirements)
# 
# Expected Files:
#     - Configuration: wsjtx_proxy.ini
#     - ADIF Log file: ~/.local/share/WSJT-X/wsjtx_log.adi
# 
# Usage:
#     - Start this script before launching WSJT-X
#     - Configure WSJT-X to use the proxy port (default: 2237)
#     - QSOs will be automatically enriched at the end of each transmission
#     - Additional software (such as gridtracker) must be configured to port 4444 instead of 2237
# 
# Author  : Christian Vanguers (ON3PWN)
# License : MIT License (or GPLv3)
# Date    : 2025-07-26
# Repo    : https://github.com/on3pwn/wsjtx-proxy/

import socket
import threading
import struct
import time
import subprocess
import os
import configparser
import re
import sqlite3
from datetime import datetime

# Load Config
CONFIG_FILE = "wsjtx_proxy.ini"
config = configparser.ConfigParser()

# Default Values
default_config = {
    "network": {
        "proxy_ip": "0.0.0.0",
        "proxy_port": "2237",
        "wsjtx_ip": "127.0.0.1",
        "wsjtx_port": "2237",
        "wsjtx_alt_port": "5237",
    },
    "clients": {
        "client_list": "127.0.0.1:4444"
    },
    "paths": {
        "adi_file": "~/.local/share/WSJT-X/wsjtx_log.adi"
    },
    "rig": {
        "rigctl_address": "localhost:4532",
        "rigctl_model": "2",
        "poll_interval": "0.5"
    },
    "database": {
        "db_file": os.path.expanduser("/home/on3pwn/.local/share/WSJT-X/ham_log.db")
    }
}
config.read(CONFIG_FILE)

# Loading parameters from ini file
PROXY_IP = config.get("network", "proxy_ip")
PROXY_PORT = config.getint("network", "proxy_port")
WSJTX_IP = config.get("network", "wsjtx_ip")
WSJTX_PORT = config.getint("network", "wsjtx_port")
WSJTX_ALT_PORT = config.getint("network", "wsjtx_alt_port")
CLIENTS = [
    tuple(client.strip().split(":")) for client in config.get("clients", "client_list").split(",")
]
CLIENTS = [(ip, int(port)) for ip, port in CLIENTS]
ADI_FILE = os.path.expanduser(config.get("paths", "adi_file"))
RIGCTL_ADDR = config.get("rig", "rigctl_address")
RIGCTL_MODEL = config.get("rig", "rigctl_model")
POLL_INTERVAL = config.getfloat("rig", "poll_interval")
DB_FILE = os.path.expanduser(config.get("database", "db_file"))

# Global variables
last_adi_size = 0
latest_dx_call = ""
max_power_measured = 0.0
latest_swr = None
latest_alc = None
latest_comp = None
latest_comp_meter = None
latest_strength = None
transmitting_state = False
latest_adif_entry = None

# Sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((PROXY_IP, PROXY_PORT))
wsjtx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

lock = threading.Lock()
measure_power_flag = threading.Event()

def patch_last_adi_entry(power_w):
    global last_adi_size, latest_dx_call
    try:
        # Parent dir creation (if necessary)
        directory = os.path.dirname(ADI_FILE)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        # Initialization (if the file does not exist)
        if not os.path.exists(ADI_FILE):
            with open(ADI_FILE, "w") as f:
                f.write("WSJT-X:\n")
                f.write("<adif_ver:5>3.1.0\n")
                f.write("<programid:6>WSJT-X\n")
                f.write("<EOH>\n")
            last_adi_size = os.path.getsize(ADI_FILE)

        with open(ADI_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            current_size = f.tell()
            if current_size <= last_adi_size:
                return
            f.seek(last_adi_size)
            new_data = f.read().decode("utf-8")

        lines = new_data.strip().split("\n")
        if not lines:
            return

        new_entry = lines[-1]
        new_entry = re.sub(r"<(\w+)\s+ll:(\d+)>", r"<\1:\2>", new_entry)

        if "<eor>" not in new_entry:
            return

        if latest_dx_call and latest_dx_call in new_entry:
            tx_power_val = f"{int(power_w)}W"
            tx_pwr_str = f"<tx_pwr:{len(tx_power_val)}>{tx_power_val}"

            if "<tx_pwr:" not in new_entry:
                if "<comment:" in new_entry:
                    new_entry = new_entry.replace("<comment:", f"{tx_pwr_str} <comment:")
                else:
                    new_entry = new_entry.replace("<eor>", f"{tx_pwr_str} <eor>")

            if "<comment:" in new_entry:
                comment_start = new_entry.find("<comment:")
                len_start = comment_start + len("<comment:")
                len_end = new_entry.find(">", len_start)
                comment_len = int(new_entry[len_start:len_end])

                comment_text_start = len_end + 1
                comment_text = new_entry[comment_text_start:comment_text_start + comment_len]

                new_comment_text = comment_text + f" - Tx Pwr {tx_power_val}"
                new_comment_len = len(new_comment_text)

                new_entry = (new_entry[:comment_start] +
                             f"<comment:{new_comment_len}>{new_comment_text}" +
                             new_entry[comment_text_start + comment_len:])
            else:
                comment_text = f"Tx Power = {tx_power_val}"
                new_entry = new_entry.replace(
                    "<eor>", f"<comment:{len(comment_text)}>{comment_text} <eor>"
                )

            with open(ADI_FILE, "rb") as f:
                all_data = f.read().decode("utf-8")

            existing_part = all_data[:last_adi_size].rstrip("\n")
            new_lines = "\n".join(lines[:-1] + [new_entry])
            updated = existing_part + "\n" + new_lines + "\n"

            with open(ADI_FILE, "w") as f:
                f.write(updated)

            print(f"ADIF line modified with power : {tx_power_val}")
            last_adi_size = len(updated.encode("utf-8"))
        else:
            last_adi_size = current_size
    except Exception as e:
        print(f"Error while patching ADIF : {e}")

def poll_rigctl_values():
    global max_power_measured, latest_swr, latest_alc, latest_comp, latest_comp_meter, latest_strength
    max_power_measured = 0.0
    latest_swr = None
    latest_alc = None
    latest_comp = None
    latest_comp_meter = None
    latest_strength = None

    while measure_power_flag.is_set():
        try:
            # RF Power
            result = subprocess.run(
                ['rigctl', '-m', RIGCTL_MODEL, '-t', RIGCTL_ADDR, 'l', 'RFPOWER_METER_WATTS'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                power_str = result.stdout.strip()
                try:
                    power = float(power_str)
                    if power > max_power_measured:
                        max_power_measured = power
                except ValueError:
                    pass

            # SWR
            result = subprocess.run(
                ['rigctl', '-m', RIGCTL_MODEL, '-t', RIGCTL_ADDR, 'l', 'SWR'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                swr_str = result.stdout.strip()
                try:
                    latest_swr = float(swr_str)
                except ValueError:
                    latest_swr = None

            # ALC
            result = subprocess.run(
                ['rigctl', '-m', RIGCTL_MODEL, '-t', RIGCTL_ADDR, 'l', 'ALC'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                alc_str = result.stdout.strip()
                try:
                    latest_alc = float(alc_str)
                except ValueError:
                    latest_alc = None

            # COMP
            result = subprocess.run(
                ['rigctl', '-m', RIGCTL_MODEL, '-t', RIGCTL_ADDR, 'l', 'COMP'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                comp_str = result.stdout.strip()
                try:
                    latest_comp = float(comp_str)
                except ValueError:
                    latest_comp = None

            # COMP_METER
            result = subprocess.run(
                ['rigctl', '-m', RIGCTL_MODEL, '-t', RIGCTL_ADDR, 'l', 'COMP_METER'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                comp_meter_str = result.stdout.strip()
                try:
                    latest_comp_meter = float(comp_meter_str)
                except ValueError:
                    latest_comp_meter = None

            # STRENGTH
            result = subprocess.run(
                ['rigctl', '-m', RIGCTL_MODEL, '-t', RIGCTL_ADDR, 'l', 'STRENGTH'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                strength_str = result.stdout.strip()
                try:
                    latest_strength = float(strength_str)
                except ValueError:
                    latest_strength = None

        except Exception as e:
            print("rigctl exception:", e)

        time.sleep(POLL_INTERVAL)

    # Final display at the end of transmission
    print(f"Max power {max_power_measured:.2f} W | SWR: {latest_swr} | ALC: {latest_alc} | COMP: {latest_comp} | COMP_METER: {latest_comp_meter} | STRENGTH: {latest_strength}")
    patch_last_adi_entry(max_power_measured)

    # Add into SQlite
    #dt_now = datetime.now().isoformat(timespec='seconds')
    #insert_power_log(dt_now, max_power_measured, latest_swr, latest_alc, latest_comp, latest_comp_meter, latest_strength)

def parse_status_message(data, return_dict=False):
    global latest_dx_call
    offset = 12

    def read_qstring(data, offset):
        length = struct.unpack(">I", data[offset:offset+4])[0]
        if length == 0xFFFFFFFF:
            return None, offset + 4
        s = data[offset+4:offset+4+length].decode("utf-8")
        return s, offset + 4 + length

    client_id, offset = read_qstring(data, offset)
    dial_freq = struct.unpack(">Q", data[offset:offset+8])[0]
    offset += 8
    mode, offset = read_qstring(data, offset)
    dx_call, offset = read_qstring(data, offset)
    report_str, offset = read_qstring(data, offset)
    tx_mode, offset = read_qstring(data, offset)
    tx_enabled = data[offset] != 0
    offset += 1
    transmitting = data[offset] != 0
    offset += 1

    latest_dx_call = dx_call if dx_call else latest_dx_call

    # Cleaning the report
    try:
        report = int(report_str)
    except (TypeError, ValueError):
        report = None

    status = "RX"
    if transmitting:
        status = "TX ONGOING"
    elif tx_enabled:
        status = "Tx Ready"

    print(f"Freq: {dial_freq} Hz | Mode: {mode} | DX: {dx_call} | Rprt: {report_str} | Tx Enabled: {tx_enabled} | Transmitting: {transmitting} status : {status}") 

    if return_dict:
        return transmitting, {
            "dx_call": dx_call,
            "report": report
        }

    return transmitting

def listen_from_wsjtx():
    wsjtx_sock.bind((WSJTX_IP, WSJTX_ALT_PORT))
    global transmitting_state, latest_adif_entry
    global dx_call, last_rcvd_report, latest_report_sent, latest_report_rcvd

    dx_call = None
    last_rcvd_report = None
    latest_report_sent = None
    latest_report_rcvd = None

    while True:
        data, addr = wsjtx_sock.recvfrom(4096)

        for client in CLIENTS:
            sock.sendto(data, client)

        if len(data) < 12:
            continue

        magic = struct.unpack(">I", data[0:4])[0]
        if magic != 0xadbccbda:
            continue

        msg_type = struct.unpack(">I", data[8:12])[0]

        if msg_type == 1:  # Status message
            # Parse status
            transmitting, parsed = parse_status_message(data, return_dict=True)

            if parsed:
                if 'dx_call' in parsed:
                    dx_call = parsed['dx_call']
                if 'report' in parsed and 'tx_mode' in parsed:
                    # On suppose report = sent report, rcvd pas toujours dispo ici
                    latest_report_sent = parsed['report']
                    if 'report_rcvd' in parsed:
                        latest_report_rcvd = parsed['report_rcvd']

            with lock:
                if transmitting and not transmitting_state:
                    transmitting_state = True
                    measure_power_flag.set()
                    threading.Thread(target=poll_rigctl_values, daemon=True).start()
                elif not transmitting and transmitting_state:
                    transmitting_state = False
                    measure_power_flag.clear()

                # At the end of transmission, we patch the adif
                if not transmitting and latest_adif_entry:
                    try:
                        enrich_adif(latest_adif_entry, max_power_measured, ADI_FILE)
                        latest_adif_entry = None
                    except Exception as e:
                        print(f"Error at adif patching : {e}")

        elif msg_type == 12:  # ADIF message
            try:
                adif_data = data[16:].decode("utf-8", errors="replace")
                print("adif message received")
                print("adif contents :")
                print(adif_data)

                # patch rst_rcvd if empty or inconsistent
                call_match = re.search(r"<call:\d+>([A-Z0-9]+)", adif_data)
                rcvd_match = re.search(r"<rst_rcvd:(\d+)>([^ <]*)", adif_data)

                if call_match:
                    adif_call = call_match.group(1)
                    if dx_call and adif_call == dx_call:
                        if rcvd_match:
                            rcvd_val = rcvd_match.group(2).strip()
                            if rcvd_val in ["", "0", "00", "9", "-99", "99", "1"]:
                                if latest_report_rcvd is not None:
                                    report_clean = f"{int(latest_report_rcvd):+03d}"
                                    report_clean = report_clean[-3:]
                                    new_chunk = f"<rst_rcvd:3>{report_clean}"
                                    adif_data = re.sub(r"<rst_rcvd:\d+>[^ <]*", new_chunk, adif_data)
                        else:
                            if latest_report_rcvd is not None:
                                report_clean = f"{int(latest_report_rcvd):+03d}"
                                report_clean = report_clean[-3:]
                                adif_data = adif_data.replace(
                                    "<rst_sent", f"<rst_rcvd:3>{report_clean} <rst_sent"
                                )

                # Saving adif foar later enrichment after TX
                latest_adif_entry = adif_data

            except Exception as e:
                print(f"Error while decoding ADIF : {e}")

def listen_from_clients():
    while True:
        data, addr = sock.recvfrom(4096)
        wsjtx_sock.sendto(data, (WSJTX_IP, WSJTX_ALT_PORT))

def enrich_adif(adif_data: str, tx_power: float, ADI_FILE: str) -> str:
    global latest_report_sent, latest_report_rcvd

    if "<EOH>" in adif_data:
        adif_data = adif_data.split("<EOH>", 1)[1].strip()
    if adif_data.startswith("WSJT-X:"):
        adif_data = adif_data[len("WSJT-X:"):].strip()

    if latest_report_sent is not None:
        rst_sent_clean = f"{int(latest_report_sent):+03d}"[-3:]
        if re.search(r"<rst_sent:\d+>[+-]?\d+", adif_data):
            adif_data = re.sub(r"(<rst_sent:\d+>)[+-]?\d+", r"\1" + rst_sent_clean, adif_data)
        else:
            if "<rst_rcvd:" in adif_data:
                adif_data = adif_data.replace("<rst_rcvd:", f"<rst_sent:3>{rst_sent_clean} <rst_rcvd:")
            else:
                adif_data = adif_data.replace("<station_callsign", f"<rst_sent:3>{rst_sent_clean} <station_callsign")

    if latest_report_rcvd is not None:
        rst_rcvd_clean = f"{int(latest_report_rcvd):+03d}"[-3:]
        if re.search(r"<rst_rcvd:\d+>[+-]?\d+", adif_data):
            adif_data = re.sub(r"(<rst_rcvd:\d+>)[+-]?\d+", r"\1" + rst_rcvd_clean, adif_data)
        else:
            if "<rst_sent:" in adif_data:
                adif_data = adif_data.replace("<rst_sent:", f"<rst_rcvd:3>{rst_rcvd_clean} <rst_sent:")
            else:
                adif_data = adif_data.replace("<station_callsign", f"<rst_rcvd:3>{rst_rcvd_clean} <station_callsign")

    tx_str = f"{round(tx_power)}W"
    if "<tx_pwr:" not in adif_data:
        adif_data = adif_data.replace("<station_callsign", f"<tx_pwr:{len(tx_str)}>{tx_str} <station_callsign")

    rst_sent_match = re.search(r"<rst_sent:\d+>([+-]?\d+)", adif_data)
    rst_sent = rst_sent_match.group(1) if rst_sent_match else "-??"
    rst_rcvd_match = re.search(r"<rst_rcvd:\d+>([+-]?\d+)", adif_data)
    rst_rcvd = rst_rcvd_match.group(1) if rst_rcvd_match else "+01"

    new_comment = f"FT8  Rcvd: {rst_rcvd} Sent: {rst_sent} - Tx Pwr {tx_str}"
    new_len = len(new_comment)
    if re.search(r"<comment:\d+>[^<]*", adif_data):
        adif_data = re.sub(r"<comment:\d+>[^<]*", f"<comment:{new_len}>{new_comment}", adif_data)
    else:
        if "<EOR>" in adif_data:
            adif_data = adif_data.replace("<EOR>", f"<comment:{new_len}>{new_comment} <EOR>")
        else:
            adif_data += f" <comment:{new_len}>{new_comment}"

    directory = os.path.dirname(ADI_FILE)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Unable to create the directory {directory} : {e}")
            raise

    need_header = True
    if os.path.exists(ADI_FILE):
        try:
            with open(ADI_FILE, "r") as f:
                content = f.read(1024)
                if "<EOH>" in content:
                    need_header = False
        except Exception as e:
            print(f"Unable to read the file {ADI_FILE} : {e}")
            raise

    try:
        with open(ADI_FILE, "a") as f:
            if need_header:
                f.write("WSJT-X:\n")
                f.write("<adif_ver:5>3.1.0\n")
                f.write("<programid:6>WSJT-X\n")
                f.write("<EOH>\n")
            f.write(adif_data.strip() + "\n")
    except Exception as e:
        print(f"Error while writing into {ADI_FILE} : {e}")
        raise

    # --- INSERTION INTO SQLITE DB ---
    #try:
    #    conn = sqlite3.connect("qso_log.db")
    #    c = conn.cursor()
    #    c.execute("""
    #        CREATE TABLE IF NOT EXISTS qso_log (
    #            id INTEGER PRIMARY KEY AUTOINCREMENT,
    #            callsign TEXT,
    #            band TEXT,
    #            freq REAL,
    #            mode TEXT,
    #            rst_sent TEXT,
    #            rst_rcvd TEXT,
    #            tx_pwr TEXT,
    #            date TEXT,
    #            time TEXT,
    #            comment TEXT
    #        )
    #    """)

    #   # Extract fields
    #    extract = lambda tag: re.search(fr"<{tag}:\d+>([^ <]*)", adif_data)
    #    call = extract("call").group(1) if extract("call") else ""
    #    band = extract("band").group(1) if extract("band") else ""
    #    freq = extract("freq").group(1) if extract("freq") else ""
    #    mode = extract("mode").group(1) if extract("mode") else ""
    #    date = extract("qso_date").group(1) if extract("qso_date") else ""
    #    time_on = extract("time_on").group(1) if extract("time_on") else ""
    #    comment = new_comment

    #    c.execute("""
    #        INSERT INTO qso_log (callsign, band, freq, mode, rst_sent, rst_rcvd, tx_pwr, date, time, comment)
    #        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    #    """, (call, band, freq, mode, rst_sent, rst_rcvd, tx_str, date, time_on, comment))

    #    conn.commit()
    #    conn.close()

    #except Exception as e:
    #    print(f"SQLite DB insert error: {e}")
    #    raise

    return adif_data

# Initialize the size of ADI file
if os.path.exists(ADI_FILE):
    last_adi_size = os.path.getsize(ADI_FILE)

t1 = threading.Thread(target=listen_from_wsjtx, daemon=True)
t2 = threading.Thread(target=listen_from_clients, daemon=True)
t1.start()
t2.start()

print("WSJTX_Proxy enabled. Ctrl+C to quit.")
while True:
    time.sleep(1)
