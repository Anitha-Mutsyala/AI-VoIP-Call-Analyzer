import os
import shutil
import subprocess

TSHARK_PATH = shutil.which("tshark")

# Windows fallback
if TSHARK_PATH is None:
    WINDOWS_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

    if os.path.exists(WINDOWS_TSHARK):
        TSHARK_PATH = WINDOWS_TSHARK
    else:
        raise RuntimeError("Tshark is not installed or not found in PATH.")


def analyze_pcap(file_path):
    """
    Reads a PCAP using Tshark and processes packets as they are produced.
    """

    cmd = [
        TSHARK_PATH,
        "-n",
        "-Q",
        "-r", file_path,
        "-Y", "rtp || sip",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "_ws.col.Protocol",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "rtp.seq",
        "-e", "rtp.timestamp",
        "-e", "rtp.ssrc",
        "-e", "rtp.p_type",
        "-e", "sip.Method",
        "-e", "sip.Status-Code"
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    packet_rows = []

    for line in process.stdout:

        line = line.strip()

        if not line:
            continue

        parts = line.split("\t")

        while len(parts) < 10:
            parts.append("")

        (
            timestamp,
            protocol,
            src,
            dst,
            seq,
            rtp_timestamp,
            ssrc,
            payload,
            sip_method,
            sip_status
        ) = parts

        try:
            timestamp = float(timestamp) if timestamp else None
        except ValueError:
            timestamp = None

        try:
            seq = int(seq) if seq else None
        except ValueError:
            seq = None

        try:
            rtp_timestamp = int(rtp_timestamp) if rtp_timestamp else None
        except ValueError:
            rtp_timestamp = None

        packet_rows.append({
            "timestamp": timestamp,
            "protocol": protocol.strip() if protocol else "Unknown",
            "src": src,
            "dst": dst,
            "seq": seq,
            "rtp_timestamp": rtp_timestamp,
            "ssrc": ssrc,
            "payload": payload,
            "sip_method": sip_method,
            "sip_status": sip_status
        })

    stderr = process.stderr.read()

    process.wait()

    if process.returncode != 0:
        raise RuntimeError(stderr)

    return packet_rows
