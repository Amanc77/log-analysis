import re
from collections import defaultdict
import csv

def parse_logs(file_path):
    """Parses the log file and returns a list of log entries."""
    logs = []
    with open(file_path, 'r') as file:
        for line in file:
            logs.append(line.strip())
    return logs

def count_requests_per_ip(logs):
    """Counts the number of requests per IP address."""
    ip_counts = defaultdict(int)
    for log in logs:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

def find_frequent_endpoints(logs):
    """Finds the most frequently accessed endpoints."""
    endpoint_counts = defaultdict(int)
    for log in logs:
        match = re.search(r'\"[A-Z]+ (.+?) HTTP', log)
        if match:
            endpoint_counts[match.group(1)] += 1
    return sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)

def detect_suspicious_activity(logs):
    """Detects suspicious activity based on failed login attempts."""
    suspicious_ips = defaultdict(int)
    for log in logs:
        if "failed login" in log.lower():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                suspicious_ips[match.group(1)] += 1
    return suspicious_ips

def save_to_csv(data, file_name):
    """Saves data to a CSV file."""
    with open(file_name, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Key", "Value"])
        writer.writerows(data.items())

def main():
    log_file = "sample.log"  # Replace with your log file name
    logs = parse_logs(log_file)

    print("Analyzing logs...")

    # Count requests per IP
    ip_counts = count_requests_per_ip(logs)
    print("\nRequests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

    # Most frequent endpoints
    frequent_endpoints = find_frequent_endpoints(logs)
    print("\nMost Frequently Accessed Endpoints:")
    for endpoint, count in frequent_endpoints[:5]:
        print(f"{endpoint}: {count}")

    # Suspicious activity
    suspicious_ips = detect_suspicious_activity(logs)
    print("\nSuspicious Activity:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed login attempts")

    # Save results to CSV
    save_to_csv(ip_counts, "ip_requests.csv")
    print("\nResults saved to 'ip_requests.csv'")

if __name__ == "__main__":
    main()
