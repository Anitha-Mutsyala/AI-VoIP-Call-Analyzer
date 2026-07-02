# AI VoIP Call Analyzer

An AI-powered VoIP network analysis application that processes **PCAP/PCAPNG** packet captures to analyze SIP and RTP traffic, evaluate call quality, and generate intelligent root cause analysis reports.

Built using **Python**, **Flask**, and **Wireshark Tshark**, the application extracts VoIP traffic, computes Quality of Service (QoS) metrics, detects network anomalies, and presents the results through an interactive web dashboard. The AI-assisted diagnosis engine helps identify potential causes of call degradation and provides actionable recommendations.

---

## 🚀 Features

* 📂 Upload and analyze PCAP/PCAPNG files
* 📡 RTP stream detection and analysis
* 📞 SIP signaling analysis (INVITE, BYE, etc.)
* 📉 Packet loss calculation
* 📈 Jitter analysis
* 🔄 SSRC change detection
* 🎯 Payload type (codec) identification
* 📊 RTP stream statistics and QoS metrics
* 🤖 AI-assisted root cause analysis
* 🎯 Confidence-based issue detection
* 💡 Troubleshooting recommendations
* 🌐 Interactive Flask web dashboard

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Frontend:** HTML5, CSS3, JavaScript
* **Packet Analysis:** Wireshark Tshark
* **Visualization:** Chart.js

---

## 📁 Project Structure

```text
PCAPAnalyzer/
│
├── analyzers/
│   ├── pcap_parser.py
│   ├── stream_analyzer.py
│   ├── metrics.py
│   ├── root_cause.py
│   ├── summarizer.py
│   ├── issue_detector.py
│   └── rtp_analyzer.py
│
├── static/
│   └── css/
│
├── templates/
│   ├── index.html
│   └── result.html
│
├── uploads/
├── reports/
├── app.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/your-username/AI-VoIP-Call-Analyzer.git
cd AI-VoIP-Call-Analyzer
```

### Install dependencies

```bash
pip install -r requirements.txt
```

If you don't have a `requirements.txt` file, install Flask manually:

```bash
pip install flask
```

### Install Wireshark

Install **Wireshark** and ensure **Tshark** is available on your system.

Update the Tshark path in `pcap_parser.py` if required:

```python
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
```

---

## ▶️ Run the Application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

Upload a PCAP or PCAPNG capture file to generate a VoIP analysis report.

---

## 📊 Metrics Analyzed

The application calculates several key VoIP Quality of Service (QoS) metrics, including:

* Total RTP packets
* Packet loss
* Packet loss percentage
* Average jitter
* RTP sequence gaps
* SSRC changes
* Payload types (codecs)
* RTP stream statistics
* SIP INVITE/BYE detection

---

## 🤖 AI-Powered Root Cause Analysis

The analyzer correlates multiple RTP and SIP metrics to identify possible causes of call quality degradation, including:

* Network congestion
* High packet loss
* Excessive jitter
* Poor endpoint connectivity
* Media server restart
* Codec or payload mismatch
* SSRC changes
* Healthy media streams

Each detected issue includes:

* Confidence score
* Severity level
* Explanation
* Recommended troubleshooting action

---

## 📈 Future Enhancements

* Mean Opinion Score (MOS) estimation
* One-way latency calculation
* RTCP packet analysis
* PDF and Excel report generation
* Multi-call detection
* Database integration
* Real-time packet capture
* Machine learning-based anomaly detection
* Interactive packet timeline visualization

---

## 📄 License

This project is licensed under the MIT License.

---

## 👩‍💻 Author

**Anitha Mutsyala**

Developed as an AI-assisted VoIP network analysis project using Python, Flask, and Wireshark Tshark to automate RTP diagnostics, QoS analysis, and intelligent root cause identification.
