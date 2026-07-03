from flask import Flask, render_template, request, send_file
import os
from io import BytesIO

from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

from analyzers.pcap_parser import analyze_pcap
from analyzers.stream_analyzer import build_streams
from analyzers.metrics import calculate_stream_metrics
from analyzers.root_cause import find_root_causes
from analyzers.summarizer import generate_ai_summary

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

latest_report = None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():

    if "file" not in request.files:
        return "No file uploaded."

    file = request.files["file"]

    if file.filename == "":
        return "No file selected."

    if not (
        file.filename.lower().endswith(".pcap")
        or file.filename.lower().endswith(".pcapng")
    ):
        return "Only .pcap or .pcapng files are supported."

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        file.filename
    )

    file.save(filepath)

    try:

        # Parse packets
        packet_rows = analyze_pcap(filepath)

        # Build RTP Streams
        streams = build_streams(packet_rows)

        stream_metrics = []

        for (src, dst), packets in streams.items():

            metric = calculate_stream_metrics(packets)

            metric["src"] = src
            metric["dst"] = dst

            stream_metrics.append(metric)

        # Detect Issues
        issues = find_root_causes(stream_metrics)

        # Call Status
        if any(issue["severity"] == "High" for issue in issues):
            status = "Poor"

        elif any(issue["severity"] == "Medium" for issue in issues):
            status = "Fair"

        else:
            status = "Good"

        # AI Summary
        summary = generate_ai_summary(streams, issues)

        # Dashboard Statistics
        stats = {
            "total_streams": len(stream_metrics),
            "total_packets": sum(
                s["packet_count"] for s in stream_metrics
            ),
            "packet_loss": sum(
                s["packet_loss"] for s in stream_metrics
            ),
            "average_jitter": round(
                sum(
                    s["average_jitter"]
                    for s in stream_metrics
                ) / max(len(stream_metrics), 1),
                2
            ),
            "ssrc_changes": sum(
                s["ssrc_changes"] for s in stream_metrics
            ),
            "streams": stream_metrics
        }

        global latest_report

        latest_report = {
            "status": status,
            "summary": summary,
            "issues": issues,
            "stats": stats
        }

        return render_template(
            "result.html",
            status=status,
            summary=summary,
            issues=issues,
            stats=stats,
            packet_loss=round(stats["packet_loss"], 2),
            jitter=stats["average_jitter"],
            streams=stats["total_streams"],
            issue_count=len(issues)
        )

    except Exception as e:

        return f"""
        <h2>Analysis Failed</h2>
        <pre>{e}</pre>
        <br>
        <a href="/">Go Back</a>
        """

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
@app.route("/download-report")
def download_report():

    global latest_report

    if latest_report is None:
        return "No analysis report available."

    styles = getSampleStyleSheet()

    buffer = BytesIO()

    pdf = SimpleDocTemplate(buffer)

    elements = []

    # Title
    elements.append(
        Paragraph("AI VoIP Call Analysis Report", styles["Title"])
    )

    elements.append(
        Paragraph(
            f"<b>Call Status:</b> {latest_report['status']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>AI Summary:</b><br/>{latest_report['summary']}",
            styles["BodyText"]
        )
    )

    stats = latest_report["stats"]

    elements.append(
        Paragraph("<br/><b>Analysis Statistics</b>", styles["Heading2"])
    )

    elements.append(
        Paragraph(
            f"Total RTP Streams: {stats['total_streams']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Total Packets: {stats['total_packets']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Packet Loss: {stats['packet_loss']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Average Jitter: {stats['average_jitter']} ms",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"SSRC Changes: {stats['ssrc_changes']}",
            styles["BodyText"]
        )
    )

    # Issues
    elements.append(
        Paragraph("<br/><b>Detected Issues</b>", styles["Heading2"])
    )

    if latest_report["issues"]:

        for issue in latest_report["issues"]:

            elements.append(
                Paragraph(
                    f"<b>Title:</b> {issue['title']}<br/>"
                    f"<b>Stream:</b> {issue['stream']}<br/>"
                    f"<b>Severity:</b> {issue['severity']}<br/>"
                    f"<b>Reason:</b> {issue['reason']}<br/>"
                    f"<b>Recommendation:</b> {issue['recommendation']}<br/>"
                    f"<b>Confidence:</b> {issue['confidence']}%<br/><br/>",
                    styles["BodyText"]
                )
            )

    else:

        elements.append(
            Paragraph(
                "No issues detected.",
                styles["BodyText"]
            )
        )

    pdf.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="VoIP_Analysis_Report.pdf",
        mimetype="application/pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)
