import requests

def check_url_access(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def check_indexed_content(url):
    try:
        response = requests.get(url, timeout=5)
        return "Index of /" in response.text or "<title>Index of" in response.text
    except requests.RequestException:
        return False

def simulate_write_access(url):
    # Simulate write attempt (safe, no actual write)
    test_url = url.rstrip("/") + "/test.txt"
    try:
        response = requests.put(test_url, data="test", timeout=5)
        return response.status_code in [200, 201, 204]
    except requests.RequestException:
        return False