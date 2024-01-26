import requests
import json
import iptc

#drop-ip
def block_ip(ip):
    rule = iptc.Rule()
    rule.src = ip
    rule.target = iptc.Target(rule, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

#accept-ip
def allow_ip(ip):
    rule = iptc.Rule()
    rule.src = ip
    rule.target = iptc.Target(rule, "ACCEPT")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

# Fetch ip metadata from API
def get_ip_metadata(ip):
    url = f"http://ipinfo.team15/ips/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
        
# Read nginx accesslog from Server
def get_access_log(path:str="/var/log/nginx/access.log"):
    lines = []
    with open(path) as f:
        for line in f:
            lines.append(line)
    return lines

def last_line_number(path:str="/var/log/nginx/access.log"):
    with open(path) as f:
        lines = f.readlines()
    return len(lines)

def check_ip(ip):
    metadata = get_ip_metadata(ip)
    
    rules_json = open("rules.json", "r")
    rules_data = json.load(rules_json)
    rules_json.close()
    #--------------------------------------------------------------------------
    #country-code
    try:
        allow = False
        if metadata["asn"]["type"] != "isp":
            block_ip(ip)
            reason = "not isp"
        elif metadata["countryCode"] not in rules_data["valid_country_codes"]:
            block_ip(ip)
            reason = "not valid country code"
        elif metadata["continentCode"] not in rules_data["optional_valid_continent_codes"]:
            block_ip(ip)
            reason = "not valid continent code"
        elif rules_data["ban_tor"] and metadata["privacy"]["tor"]:
            block_ip(ip)
            reason = "tor"
        elif rules_data["ban_vpn"] and metadata["privacy"]["vpn"]:
            block_ip(ip)
            reason = "vpn"
        elif rules_data["ban_hosting"] and metadata["asn"]["type"] == "hosting":
            block_ip(ip)
            reason = "hosting"
        elif rules_data["ban_relay"] and metadata["privacy"]["relay"]:
            block_ip(ip)
            reason = "relay"
        else:
            allow = True
            allow_ip(ip)
        if not allow:
            da = open("denied_access.log", "a")
            da.write(f"{ip} {reason}\n")
            da.close()
    except:
        pass
old_start_line = last_line_number()
while True:
    end_line = last_line_number()
    lines = get_access_log()
    for line in lines[old_start_line:end_line]:
        ip = line.split(" ")[0]
        check_ip(ip)
        

    old_start_line = end_line