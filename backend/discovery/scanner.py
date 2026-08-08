"""
scanner.py
==========
RESPONSIBILITY: Run Nmap. Nothing else.

This file does NOT parse XML and does NOT touch MongoDB. It only
knows how to invoke the `nmap` command-line tool and hand back the
path to the XML file it produced. This strict boundary means the
rest of the Discovery Engine (parser.py, database.py) never needs to
know or care HOW the scan was performed.

Requires: Nmap installed and available on your system PATH.
See README.md -> "Nmap Installation" for setup instructions.
"""

import subprocess
import os
from datetime import datetime


def run_scan(target: str, output_dir: str = "data") -> str:
    """
    Run an Nmap scan against `target` and save the raw results as XML.

    Args:
        target: An IP address, hostname, or CIDR range
                (e.g. "192.168.56.101" or "192.168.56.0/24").
                This should be a device/network YOU control
                (e.g. your Metasploitable2 VM in VirtualBox).
        output_dir: Folder where the XML result file is saved.

    Returns:
        The file path to the saved XML scan result.

    Nmap flags used:
        -oX <file>   -> write output in XML format (what parser.py reads)
        -sV          -> detect service/version info on open ports
        -O           -> detect operating system (requires admin/root privileges)
        -T4          -> reasonably fast timing template (safe for a lab network)

    NOTE: -O (OS detection) requires elevated privileges.
        - Windows: run your terminal "as Administrator"
        - Linux/Mac: run with `sudo`
    If you don't have elevated privileges, remove "-O" from the
    command list below -- the scan will still work, just without OS
    guesses (operating_system will show as "Unknown" after parsing).
    """
    # Make sure the output folder exists before we try to write into it
    os.makedirs(output_dir, exist_ok=True)

    # Build a unique filename so repeated scans don't overwrite each other
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_path = os.path.join(output_dir, f"scan_{timestamp}.xml")

    command = ["nmap", "-oX", xml_path, "-sV", "-O", "-T4", target]

    print(f"[scanner] Running: {' '.join(command)}")

    try:
        # check=True -> raises CalledProcessError if nmap exits with an error
        # capture_output=True -> lets us show Nmap's own error message if it fails
        subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError(
            "Nmap was not found on your system PATH. "
            "Install it first (see README.md -> Nmap Installation)."
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Nmap scan failed: {e.stderr}")

    print(f"[scanner] Scan complete. Raw XML saved to: {xml_path}")
    return xml_path
