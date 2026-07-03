def calculate_stream_metrics(stream_packets):
    """
    Calculates quality metrics for a single RTP stream.
    """

    packet_count = len(stream_packets)

    packet_loss = 0
    sequence_gaps = 0
    ssrc_changes = 0

    payload_types = set()

    last_seq = None
    last_ssrc = None

    arrival_times = []

    # Process RTP packets
    for packet in stream_packets:

        if packet["payload"]:
            payload_types.add(packet["payload"])

        if packet["timestamp"] is not None:
            arrival_times.append(packet["timestamp"])

        # -----------------------------
        # RTP Sequence Analysis
        # -----------------------------
        seq = packet["seq"]

        if seq is not None:

            if last_seq is not None:

                # RTP sequence wraparound
                if seq < last_seq and (last_seq - seq) > 30000:
                    gap = (seq + 65536) - last_seq - 1

                # Normal increasing sequence
                elif seq > last_seq:
                    gap = seq - last_seq - 1

                # Duplicate or out-of-order packet
                else:
                    gap = 0

                if gap > 0:
                    packet_loss += gap
                    sequence_gaps += 1

            last_seq = seq

        # -----------------------------
        # SSRC Change Detection
        # -----------------------------
        if packet["ssrc"]:

            if last_ssrc is not None and packet["ssrc"] != last_ssrc:
                ssrc_changes += 1

            last_ssrc = packet["ssrc"]

    # -----------------------------
    # Packet Loss Percentage
    # -----------------------------
    expected_packets = packet_count + packet_loss

    if expected_packets > 0:
        packet_loss_percent = round(
            (packet_loss / expected_packets) * 100,
            2
        )
    else:
        packet_loss_percent = 0

    # -----------------------------
    # Jitter Calculation
    # -----------------------------
    average_jitter = 0

    if len(arrival_times) > 2:

        deltas = []

        for i in range(1, len(arrival_times)):
            deltas.append(
                arrival_times[i] - arrival_times[i - 1]
            )

        variations = []

        for i in range(1, len(deltas)):
            variations.append(
                abs(deltas[i] - deltas[i - 1])
            )

        if variations:
            average_jitter = round(
                sum(variations) / len(variations),
                4
            )

    return {
        "packet_count": packet_count,
        "packet_loss": packet_loss,
        "packet_loss_percent": packet_loss_percent,
        "sequence_gaps": sequence_gaps,
        "average_jitter": average_jitter,
        "ssrc_changes": ssrc_changes,
        "payload_types": sorted(payload_types)
    }
