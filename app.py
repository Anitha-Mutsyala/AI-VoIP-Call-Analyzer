from flask import Flask, render_template, request
import os

from analyzers.pcap_parser import analyze_pcap
from analyzers.stream_analyzer import build_streams
from analyzers.metrics import calculate_stream_metrics
from analyzers.root_cause import find_root_causes
from analyzers.summarizer import generate_ai_summary

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


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

        # Overall call status
        if any(issue["severity"] == "High" for issue in issues):
            status = "Poor"

        elif any(issue["severity"] == "Medium" for issue in issues):
            status = "Fair"

        else:
            status = "Good"

        # AI Summary
        summary = generate_ai_summary(streams, issues)

        # Dashboard statistics
        stats = {
            "total_streams": len(stream_metrics),
            "total_packets": sum(
                s["packet_count"]
                for s in stream_metrics
            ),
            "packet_loss": sum(
                s["packet_loss"]
                for s in stream_metrics
            ),
            "average_jitter": round(
                sum(
                    s["average_jitter"]
                    for s in stream_metrics
                ) / max(len(stream_metrics), 1),
                2
            ),
            "ssrc_changes": sum(
                s["ssrc_changes"]
                for s in stream_metrics
            ),
            "streams": stream_metrics
        }

        return render_template(
            "result.html",
            status=status,
            summary=summary,
            issues=issues,
            stats=stats,

            packet_loss=round(stats["packet_loss"],2),
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


if __name__ == "__main__":
    app.run(debug=True)
