# WSJT-X UDP Proxy (with TX Power Injection)

## About

This is a lightweight UDP proxy for [WSJT-X](https://physics.princeton.edu/pulsar/k1jt/wsjtx.html), designed to intercept, enrich, and forward digital mode QSO messages — with a particular focus on **injecting real TX power** into ADIF logs.

> Because making a QSO at 1W isn't the same as at 100W and your QSO partners are interested to know the difference 😉

---

## Why this project?

When I started experimenting with WSJT-X, I was amazed by how accessible and efficient it was for digital modes like FT8.  
But I quickly noticed a limitation: **the transmitted power is not included in the ADIF logs or comments**.

As a QRP enthusiast, this felt like a missing piece especially when some of my intercontinental QSOs were made at just **1W** or **5W**, not 100W (in fact it's a way of speaking and it never was 100W because my license and the Belgian legislation limits me to 25W in HF).

Unfortunately:
- I'm not a C++ developer
- but I can manage Python well enough to solve problems
- and I come from an **ethical hacking / cybersecurity background**

So... I looked into WSJT-X’s architecture and discovered it emits structured UDP messages used notably by tools like GridTracker.  Naturally, the idea was born: create a simple **MITM (now “on-path”) UDP proxy** that:

- intercepts WSJT-X's UDP traffic  
- reads & decodes Status and ADIF messages  
- re-forwards the exact same message to other apps (like GridTracker) totally transparently  
- enriches them by injecting **measured TX power** (via `rigctl`) into comments  
- saves enriched QSOs into a local ADIF file

---

## Features

- Transparent UDP proxy between WSJT-X and external tools
- Live `rigctl` polling for:
  - TX power (watts)
  - SWR, ALC, COMP, RX strength
- ADIF message parsing and enrichment
- ADIF log writing to `~/.local/share/WSJT-X/wsjtx_log.adi`
- Zero external dependencies (pure Python + hamlib)

---

## Requirements

- Python 3.7+
- `rigctl` from [hamlib](https://hamlib.github.io/)  
  → Install with: `sudo apt install hamlib`

No pip packages required.

---

## Usage

1. Clone this repo
2. Configure `udp_proxy.ini` (default ports and rigctl setup)
3. Run the proxy **before starting WSJT-X**:
   ```bash
   python3 udp_proxy.py
4. Configure WSJT-X to use the proxy port (2237 by default)
5. Connect tools like GridTracker to the proxy's output port (usually port 4444)
    - Make sure gridtracker shows status messages such as "Receive/Transmit/Decode"
6. After transmission, the proxy will:
    - inject real TX power into ADIF logs
    - transparently forward everything to clients

## License
This project is licensed under the GNU General Public License v3.0
See the LICENSE file for full terms.

## Author
Made with ham spirit by ON3PWN
Feel free to fork, improve, or suggest patches!
