def detect_call_issues(root_causes):

    issues = []

    for stream in root_causes:

        cause = stream["cause"]

        if cause == "Healthy Stream":
            continue

        issue = {

            "title": cause,

            "severity": "Medium",

            "reason": "",

            "recommendation": "",

            "stream": f'{stream["src"]} → {stream["dst"]}',

            "confidence": stream["confidence"]

        }

        if cause == "Poor Client Internet":

            issue["severity"] = "High"

            issue["reason"] = "High RTP packet loss and jitter detected from client."

            issue["recommendation"] = "Check client's Wi-Fi, ISP or VPN."

        elif cause == "Network Congestion":

            issue["severity"] = "High"

            issue["reason"] = "Packet loss and sequence gaps indicate congestion."

            issue["recommendation"] = "Inspect network path and bandwidth."

        elif cause == "Media Server Restart":

            issue["severity"] = "Medium"

            issue["reason"] = "SSRC changed during call."

            issue["recommendation"] = "Inspect media server logs."

        elif cause == "Codec Change":

            issue["severity"] = "Low"

            issue["reason"] = "Payload type changed during RTP."

            issue["recommendation"] = "Verify codec negotiation."

        issues.append(issue)

    return issues
