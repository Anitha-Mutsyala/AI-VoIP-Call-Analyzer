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

    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        return "Only .pcap or .pcapng files are supported."

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    try:

        # Parse packets
        packet_rows = analyze_pcap(filepath)

        # Build RTP streams
        streams = build_streams(packet_rows)

        stream_metrics = []

        for (src, dst), packets in streams.items():

            metric = calculate_stream_metrics(packets)

            metric["src"] = src
            metric["dst"] = dst

            stream_metrics.append(metric)

        # Detect issues
        issues = find_root_causes(stream_metrics)

        # Call Quality
        if any(i["severity"] == "High" for i in issues):
            status = "Poor"
        elif any(i["severity"] == "Medium" for i in issues):
            status = "Fair"
        else:
            status = "Good"

        summary = generate_ai_summary(streams, issues)

        # ----------------------------
        # Dashboard Statistics
        # ----------------------------

        total_packets = sum(s["packet_count"] for s in stream_metrics)
        total_lost = sum(s["packet_loss"] for s in stream_metrics)

        packet_loss_percent = 0

        if (total_packets + total_lost) > 0:
            packet_loss_percent = round(
                (total_lost / (total_packets + total_lost)) * 100,
                2
            )

        average_jitter = round(
            sum(s["average_jitter"] for s in stream_metrics)
            / max(len(stream_metrics), 1),
            2
        )

        stats = {
            "total_streams": len(stream_metrics),
            "total_packets": total_packets,
            "packet_loss": total_lost,
            "packet_loss_percent": packet_loss_percent,
            "average_jitter": average_jitter,
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
            packet_loss=stats["packet_loss_percent"],
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


@app.route("/download-report")
def download_report():

    global latest_report

    if latest_report is None:
        return "No report available."

    buffer = BytesIO()

    pdf = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

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
        Paragraph("<br/><b>Statistics</b>", styles["Heading2"])
    )

    elements.append(
        Paragraph(
            f"Total RTP Streams: {stats['total_streams']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Total RTP Packets: {stats['total_packets']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Packet Loss: {stats['packet_loss_percent']}%",
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

    elements.append(
        Paragraph("<br/><b>Detected Issues</b>", styles["Heading2"])
    )

    if latest_report["issues"]:

        for issue in latest_report["issues"]:

            elements.append(
                Paragraph(
                    f"""
                    <b>{issue['title']}</b><br/>
                    <b>Severity:</b> {issue['severity']}<br/>
                    <b>Stream:</b> {issue['stream']}<br/>
                    <b>Reason:</b> {issue['reason']}<br/>
                    <b>Recommendation:</b> {issue['recommendation']}<br/>
                    <b>Confidence:</b> {issue['confidence']}%
                    """,
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
