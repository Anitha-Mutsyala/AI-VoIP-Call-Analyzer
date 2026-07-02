def generate_ai_summary(streams, issues):

    summary = []

    summary.append("AI CALL QUALITY ANALYSIS")
    summary.append("=" * 50)

    summary.append("")
    summary.append(f"RTP Streams Analysed : {len(streams)}")
    summary.append(f"Issues Detected      : {len(issues)}")
    summary.append("")

    if len(issues) == 0:

        summary.append("No significant RTP quality issues were detected.")
        summary.append("Media transmission appears stable.")
        summary.append("Voice quality is expected to be good.")

        return "\n".join(summary)

    high = len([i for i in issues if i["severity"] == "High"])
    medium = len([i for i in issues if i["severity"] == "Medium"])

    summary.append(f"High Severity Issues   : {high}")
    summary.append(f"Medium Severity Issues : {medium}")
    summary.append("")

    summary.append("ROOT CAUSE SUMMARY")
    summary.append("-" * 40)

    causes = {}

    for issue in issues:

        title = issue["title"]

        causes[title] = causes.get(title, 0) + 1

    for title, count in causes.items():

        summary.append(f"• {title} : {count} occurrence(s)")

    summary.append("")
    summary.append("Overall Assessment")

    if high >= 3:

        summary.append(
            "Critical call degradation detected. Voice quality is expected to be poor."
        )

    elif high >= 1:

        summary.append(
            "Noticeable voice quality degradation detected."
        )

    else:

        summary.append(
            "Minor quality issues detected."
        )

    return "\n".join(summary)
