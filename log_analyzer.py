import datetime
import argparse
import anthropic
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
    
)

class LogAnalyzerError(Exception):
    pass

class LogAnalyzer:
    def __init__(self, input_file: str, output_file: str) -> None:
        """Initialize LogAnalyzer with input and output file paths."""
        self.input_file = input_file
        self.output_file = output_file
        self.logs = []
        self.critical = []
        self.counts = {}
        self.ai_analysis = ""

    def load(self) -> None:
        """Load and parse log entries from the input file into self.logs."""

        try:
            file_handle = open(self.input_file, "r", encoding="utf-8")
        except FileNotFoundError:
            raise LogAnalyzerError(f"File '{self.input_file}' not found.")
    
        with file_handle as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ", 3)
                log = {
                    "time": parts[0] + " " + parts[1],
                    "level": parts[2],
                    "message": parts[3]
                }
                self.logs.append(log)
        if not self.logs:
            raise LogAnalyzerError(f"File '{self.input_file}' is empty or contains no valid log entries.")

    def filter(self) -> None:
        """Filter log entries by severity level into self.critical."""
        self.critical = []
        for log in self.logs:
            if log["level"] in ["WARNING", "ERROR", "CRITICAL"]:
                self.critical.append(log)

    def count(self) -> None:
        """Count log entries by severity level and store results in self.counts."""
        self.counts = {}
        for log in self.logs:
            level = log["level"]
            if level in self.counts:
                self.counts[level] += 1
            else:
                self.counts[level] = 1

    def detect_brute_force(self, threshold: int = 3, window_seconds: int = 60) -> list:
        """
        Detect brute force login attempts in log data.

        Args:
            threshold: Minimum number of failed attempts to trigger an alert.
            window_seconds: Time window in seconds to check for repeated attempts.

        Returns:
            List of dicts with keys: ip, count, first, last.
        """
        attempts = {}
        for log in self.logs:
            if log["level"] == "WARNING" and "Failed login attempt" in log["message"]:
                ip = log["message"].split("from ")[-1]
                if ip not in attempts:
                    attempts[ip] = []
                attempts[ip].append(log["time"])
        alerts = []
        for ip, times in attempts.items():
            timestamps = [datetime.datetime.strptime(t, "%Y-%m-%d %H:%M:%S") for t in times]
            timestamps.sort()
            for i in range(len(timestamps)):
                window = [t for t in timestamps if t >= timestamps[i] and (t - timestamps[i]).seconds <= window_seconds]
                if len(window) >= threshold:
                    alerts.append({
                    "ip": ip,
                    "count": len(window),
                    "first": timestamps[i].strftime("%H:%M:%S"),
                    "last": window[-1].strftime("%H:%M:%S")
                    })
                    break
        return alerts                    

    def analyze(self) -> None:
        """Send critical log entries to Claude AI and store analysis in self.ai_analysis."""
        if not self.critical:
            self.ai_analysis = "No events requiring attention."
            return
        log_text = "\n".join(
            f"[{log['level']}] {log['time']} — {log['message']}"
            for log in self.critical
        )
        client = anthropic.Anthropic()
        message = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=500,
            system="""You are a senior SOC analyst reviewing Windows enterprise logs.
Always respond in this exact format:
THREAT LEVEL: [CRITICAL/HIGH/MEDIUM/LOW]
SUMMARY: [one sentence, max 20 words]
FINDINGS:
- [finding]
IMMEDIATE ACTIONS:
- [action]

Be concise. No markdown. No headers. Plain text only.""",
            messages=[
                {
                    "role": "user",
                    "content": f"Analyze these security logs:\n{log_text}"
                }
            ]
        )
        self.ai_analysis = message.content[0].text

    def save(self) -> None:
        """Write the full analysis report to the output file."""
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(f"IT Log Analysis Report\n")
            f.write(f"Generated: {datetime.datetime.now()}\n")
            f.write(f"{'='*40}\n\n")
            f.write(f"SUMMARY\n")
            for level, count in self.counts.items():
                f.write(f"  {level}: {count}\n")
            f.write(f"\nEVENTS REQUIRING ATTENTION ({len(self.critical)})\n")
            f.write(f"{'='*40}\n")
            for entry in self.critical:
                f.write(f"[{entry['level']}] {entry['time']} — {entry['message']}\n")
            f.write(f"\nAI SECURITY ANALYSIS\n")
            f.write(f"{'='*40}\n")
            f.write(self.ai_analysis + "\n")


parser = argparse.ArgumentParser(description="IT Log Analyzer")
parser.add_argument("--input", required=True, help="Path to log file")
parser.add_argument("--output", required=True, help="Path to output report")
args = parser.parse_args()

try:
    analyzer = LogAnalyzer(args.input, args.output)
    analyzer.load()
    analyzer.filter()
    analyzer.count()
    analyzer.analyze()
    analyzer.save()
except LogAnalyzerError as e:
    logging.error(str(e))
    exit(1)

brute_force = analyzer.detect_brute_force()
if brute_force:
    for alert in brute_force:
        logging.warning(f"BRUTE FORCE DETECTED: {alert['ip']} — {alert['count']} attempts ({alert['first']} - {alert['last']})")

logging.info(f"Found {len(analyzer.critical)} entries requiring attention.")
logging.info(f"Statistics: {analyzer.counts}")
logging.info("AI analysis completed.")
logging.info(f"Report saved to {analyzer.output_file}")
