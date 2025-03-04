import re
from django.shortcuts import render
from .models import LogFile

# Function to scan log file for suspicious activity
def scan_logs(file_path):
    patterns = [
        "failed login",
        "unauthorized access",
        "malicious activity detected",
        "brute force attack"
    ]
    alerts = []

    with open(file_path, "r") as file:
        for line in file:
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    alerts.append(f"ALERT: {pattern.upper()} DETECTED - {line.strip()}")

    return alerts

# View to handle file uploads and scanning
def upload_log(request):
    if request.method == "POST" and request.FILES.get("file"):
        log = LogFile(file=request.FILES["file"])
        log.save()
        alerts = scan_logs(log.file.path)
        return render(request, "monitor/log_results.html", {"alerts": alerts})

    return render(request, "monitor/upload_log.html")
