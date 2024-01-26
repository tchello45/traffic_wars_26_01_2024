import requests
import json

def get_ip_metadata(ip):
    url = f"http://ipinfo.team15/ips/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
