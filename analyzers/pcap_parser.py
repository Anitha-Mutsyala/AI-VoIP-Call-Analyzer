import subprocess

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def analyze_pcap(file_path):
    """
    Reads a PCAP file using Tshark and returns all packets as a list of dictionaries.
    Other modules will calculate metrics and detect issues.
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

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise Exception(result.stderr)

    packet_rows = []

    for line in result.stdout.splitlines():

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
        except:
            timestamp = None

        try:
            seq = int(seq) if seq else None
        except:
            seq = None

        try:
            rtp_timestamp = int(rtp_timestamp) if rtp_timestamp else None
        except:
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

    return packet_rows
