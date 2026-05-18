import datetime
import argparse
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
        logging.error(f"Plik '{filepath}' nie istnieje.")
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
        logging.error(f"Plik '{filepath}' jest pusty lub nie zawiera poprawnych logów.")
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


parser = argparse.ArgumentParser(description="IT Log Analyzer")
parser.add_argument("--input", required=True, help="Path to log file")
parser.add_argument("--output", required=True, help="Path to output report")
args = parser.parse_args()

logs = load_logs_from_file(args.input)

def save_report(critical, counts, output_file):
    with open(output_file, "w") as f:
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

critical = filter_critical(logs)

logging.info(f"Znaleziono {len(critical)} wpisów wymagających uwagi.")
for entry in critical:
    logging.info(f"  [{entry['level']}] {entry['time']} — {entry['message']}")

counts = count_by_level(logs)
logging.info(f"Statystyki: {counts}")

save_report(critical, counts, args.output)
logging.info(f"Raport zapisany do {args.output}")