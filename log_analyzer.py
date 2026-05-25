import datetime
import argparse
import anthropic
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def load_logs_from_file(filepath):
    logs = []
    try:
        file_handle = open(filepath, "r")
    except FileNotFoundError:
        logging.error(f"File '{filepath}' not found.")
        exit(1)
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
            logs.append(log)
    if not logs:
        logging.error(f"File '{filepath}' is empty or contains no valid log entries.")
        exit(1)
    return logs

def filter_critical(logs):
    result = []
    for log in logs:
        if log["level"] in ["WARNING", "ERROR", "CRITICAL"]:
            result.append(log)
    return result

def count_by_level(logs):
    counts = {}
    for log in logs:
        level = log["level"]
        if level in counts:
            counts[level] += 1
        else:
            counts[level] = 1
    return counts

def analyze_with_ai(critical_logs):
    if not critical_logs:
        return "No events requiring attention."

    log_text = "\n".join(
        f"[{log['level']}] {log['time']} — {log['message']}"
        for log in critical_logs
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

    return message.content[0].text


parser = argparse.ArgumentParser(description="IT Log Analyzer")
parser.add_argument("--input", required=True, help="Path to log file")
parser.add_argument("--output", required=True, help="Path to output report")
args = parser.parse_args()

logs = load_logs_from_file(args.input)

def save_report(critical, counts, output_file, ai_analysis):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"IT Log Analysis Report\n")
        f.write(f"Generated: {datetime.datetime.now()}\n")
        f.write(f"{'='*40}\n\n")
        
        f.write(f"SUMMARY\n")
        for level, count in counts.items():
            f.write(f"  {level}: {count}\n")
        
        f.write(f"\nEVENTS REQUIRING ATTENTION ({len(critical)})\n")
        f.write(f"{'='*40}\n")
        for entry in critical:
            f.write(f"[{entry['level']}] {entry['time']} — {entry['message']}\n")

        f.write(f"\nAI SECURITY ANALYSIS\n")
        f.write(f"{'='*40}\n")
        f.write(ai_analysis + "\n")    

critical = filter_critical(logs)

logging.info(f"Found  {len(critical)} entries requiring attention.")
for entry in critical:
    logging.info(f"  [{entry['level']}] {entry['time']} — {entry['message']}")

counts = count_by_level(logs)
logging.info(f"Statistics: {counts}")

ai_analysis = analyze_with_ai(critical)
logging.info("AI analysis completed.")

save_report(critical, counts, args.output, ai_analysis)
logging.info(f"Report saved to {args.output}")
