import subprocess
import shutil

TSHARK_PATH = shutil.which("tshark")

if TSHARK_PATH is None:
    raise RuntimeError("Tshark is not installed on this server.")


def analyze_pcap(file_path):
    """
    Reads a PCAP file using Tshark and returns packets as a list of dictionaries.
    Uses streaming instead of loading the entire output into memory.
    """

    cmd = [
        TSHARK_PATH,
        "-r", file_path,
        "-T", "fields",
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

        parts = line.rstrip("\n").split("\t")

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
    return_code = process.wait()

    if return_code != 0:
        raise Exception(stderr)

    return packet_rows
