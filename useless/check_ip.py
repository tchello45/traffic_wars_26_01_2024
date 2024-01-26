import get_metadata
import json
import firewall
def check_ip(ip):
    metadata = get_metadata.get_ip_metadata(ip)
    
    rules_json = open("rules.json", "r")
    data = json.load(rules_json)
    rules_json.close()
    #--------------------------------------------------------------------------
    # Ban asn
    if metadata["asn"]["type"] != "isp":
        firewall.block_ip(ip)
    #Ban country-code
    elif metadata["countryCode"] not in data["valid_country_codes"]:
        firewall.block_ip(ip)

    elif metadata["continentCode"] not in data["optional_valid_continent_codes"]:
        firewall.block_ip(ip)
        pass