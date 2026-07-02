from collections import defaultdict

def analyze_rtp(rtp_packets):
    metrics = {
        "packet_loss": 0,
        "packet_loss_percent": 0,
        "sequence_gaps": 0,
        "ssrc_changes": 0,
        "payload_changes": 0,
        "streams": {},
        "issues": []
    }

    previous_seq = {}
    previous_ssrc = {}
    previous_payload = {}

    total_rtp = 0
    lost_packets = 0

    for pkt in rtp_packets:

        stream = (pkt["src"], pkt["dst"])

        total_rtp += 1

        seq = pkt["seq"]
        ssrc = pkt["ssrc"]
        payload = pkt["payload"]

        if stream not in previous_seq:
            previous_seq[stream] = seq
        else:

            gap = seq - previous_seq[stream] - 1

            if gap > 0:
                lost_packets += gap
                metrics["sequence_gaps"] += 1

            previous_seq[stream] = seq

        if stream in previous_ssrc:

            if previous_ssrc[stream] != ssrc:
                metrics["ssrc_changes"] += 1

        previous_ssrc[stream] = ssrc

        if stream in previous_payload:

            if previous_payload[stream] != payload:
                metrics["payload_changes"] += 1

        previous_payload[stream] = payload

    metrics["packet_loss"] = lost_packets

    if total_rtp:
        metrics["packet_loss_percent"] = round(
            lost_packets /
            (lost_packets + total_rtp) * 100,
            2
        )

    return metrics
