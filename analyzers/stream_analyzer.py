from collections import defaultdict


def build_streams(packet_rows):
    """
    Groups RTP packets into streams based on Source IP and Destination IP.
    """

    streams = defaultdict(list)

    for packet in packet_rows:

        if packet["protocol"] != "RTP":
            continue

        key = (
            packet["src"],
            packet["dst"]
        )

        streams[key].append(packet)

    return streams


def summarize_streams(streams):
    """
    Converts grouped RTP streams into a readable list.
    """

    summary = []

    for (src, dst), packets in streams.items():

        summary.append({

            "src": src,

            "dst": dst,

            "packet_count": len(packets),

            "packets": packets

        })

    return summary
