def find_root_causes(stream_metrics):

    issues = []

    for stream in stream_metrics:

        stream_name = f"{stream['src']} → {stream['dst']}"

        loss = stream["packet_loss_percent"]
        jitter = stream["average_jitter"]
        gaps = stream["sequence_gaps"]
        ssrc = stream["ssrc_changes"]
        payloads = stream["payload_types"]

        # -------------------------
        # Severe Packet Loss
        # -------------------------

        if loss >= 10:

            issues.append({

                "title": "Severe Voice Breakage",

                "stream": stream_name,

                "severity": "High",

                "reason":
                f"Packet loss reached {loss}% ({stream['packet_loss']} RTP packets missing).",

                "recommendation":
                "Investigate client internet connection, congestion, VPN, Wi-Fi quality or packet drops.",

                "confidence": 98

            })

        elif loss >= 3:

            issues.append({

                "title": "Minor Voice Breakage",

                "stream": stream_name,

                "severity": "Medium",

                "reason":
                f"Packet loss of {loss}% detected.",

                "recommendation":
                "Monitor network quality and verify RTP delivery.",

                "confidence": 90

            })

        # -------------------------
        # High Jitter
        # -------------------------

        if jitter >= 0.05:

            issues.append({

                "title": "High RTP Jitter",

                "stream": stream_name,

                "severity": "High",

                "reason":
                f"Average jitter is {jitter:.4f} seconds causing irregular packet arrival.",

                "recommendation":
                "Check unstable client network or WAN congestion.",

                "confidence": 94

            })

        elif jitter >= 0.02:

            issues.append({

                "title": "Moderate RTP Jitter",

                "stream": stream_name,

                "severity": "Medium",

                "reason":
                f"Average jitter is {jitter:.4f} seconds.",

                "recommendation":
                "Network latency fluctuations detected.",

                "confidence": 87

            })

        # -------------------------
        # Sequence Gaps
        # -------------------------

        if gaps >= 20:

            issues.append({

                "title": "Multiple RTP Sequence Gaps",

                "stream": stream_name,

                "severity": "High",

                "reason":
                f"{gaps} RTP sequence discontinuities detected.",

                "recommendation":
                "Likely caused by packet drops or network congestion.",

                "confidence": 95

            })

        # -------------------------
        # SSRC Changes
        # -------------------------

        if ssrc > 0:

            issues.append({

                "title": "Media Stream Restart",

                "stream": stream_name,

                "severity": "Medium",

                "reason":
                f"SSRC changed {ssrc} times during the RTP stream.",

                "recommendation":
                "Possible media server restart, call transfer or bot media restart.",

                "confidence": 93

            })

        # -------------------------
        # Codec Change
        # -------------------------

        if len(payloads) > 1:

            issues.append({

                "title": "Codec/Payload Change",

                "stream": stream_name,

                "severity": "Medium",

                "reason":
                f"Multiple RTP payload types detected: {', '.join(payloads)}.",

                "recommendation":
                "Possible codec renegotiation or transcoding.",

                "confidence": 91

            })

    return issues
