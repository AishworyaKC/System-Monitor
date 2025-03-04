import requests
from bs4 import BeautifulSoup
from django.http import JsonResponse
from urllib.parse import urljoin

def scan(request):
    if request.method == "POST":
        import json
        data = json.loads(request.body)
        url = data.get("url")

        if not url:
            return JsonResponse({"error": "URL is required"}, status=400)

        vulnerabilities = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 403:
                return JsonResponse({"error": "403 Forbidden – Access Denied by Target Website"}, status=403)

            html_content = response.text
            headers_received = response.headers

        except requests.exceptions.RequestException:
            return JsonResponse({"error": "Failed to fetch URL"}, status=500)

        # 🛑 CHECK MISSING SECURITY HEADERS
        security_headers = ["Strict-Transport-Security", "X-Content-Type-Options"]
        missing_headers = [h for h in security_headers if h not in headers_received]
        if missing_headers:
            vulnerabilities.append(f"Missing HTTP Security Headers: {', '.join(missing_headers)}")

        # 🔄 CHECK FOR OUTDATED SOFTWARE IN HEADERS
        if "Server" in headers_received:
            server_version = headers_received["Server"]
            if "Apache/2.4.6" in server_version:  # Example check
                vulnerabilities.append("Outdated Software Version Detected: Apache 2.4.6")

        # 📝 CHECK FOR FORMS WITH BAD SECURITY ATTRIBUTES
        soup = BeautifulSoup(html_content, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            method = form.get("method", "").lower()
            if method != "post":
                vulnerabilities.append(f"Form without proper method attribute: {form.get('action', 'Unknown')}")

        return JsonResponse({"url": url, "vulnerabilities": vulnerabilities})

    return JsonResponse({"error": "Invalid request method"}, status=405)
