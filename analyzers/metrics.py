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

    # -----------------------------
    # Process every RTP packet
    # -----------------------------

    for packet in stream_packets:

        if packet["payload"]:
            payload_types.add(packet["payload"])

        if packet["timestamp"] is not None:
            arrival_times.append(packet["timestamp"])

        # -----------------------------
        # Sequence Number Analysis
        # -----------------------------

        seq = packet["seq"]

        if seq is not None:

            if last_seq is not None:

                gap = seq - last_seq - 1

                # Handle RTP sequence wraparound
                if gap < -30000:
                    gap += 65536

                if gap > 0:
                    packet_loss += gap
                    sequence_gaps += 1

            last_seq = seq

        # -----------------------------
        # SSRC Change Detection
        # -----------------------------

        if packet["ssrc"]:

            if last_ssrc is not None:

                if packet["ssrc"] != last_ssrc:
                    ssrc_changes += 1

            last_ssrc = packet["ssrc"]

    # -----------------------------
    # Packet Loss %
    # -----------------------------

    packet_loss_percent = 0

    if packet_count > 0:

        packet_loss_percent = round(

            (packet_loss / (packet_count + packet_loss)) * 100,

            2

        )

    # -----------------------------
    # Jitter Calculation
    # -----------------------------

    average_jitter = 0

    if len(arrival_times) > 2:

        deltas = []

        for i in range(1, len(arrival_times)):

            deltas.append(

                arrival_times[i] -

                arrival_times[i - 1]

            )

        variation = []

        for i in range(1, len(deltas)):

            variation.append(

                abs(

                    deltas[i] -

                    deltas[i - 1]

                )

            )

        if variation:

            average_jitter = round(

                sum(variation) / len(variation),

                4

            )

    # -----------------------------
    # Return Metrics
    # -----------------------------

    return {

        "packet_count": packet_count,

        "packet_loss": packet_loss,

        "packet_loss_percent": packet_loss_percent,

        "sequence_gaps": sequence_gaps,

        "average_jitter": average_jitter,

        "ssrc_changes": ssrc_changes,

        "payload_types": sorted(list(payload_types))

    }
