import re

ipv4_v2 = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'
domain = r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'

def is_ip_v4(address):

    result = None
    if address:
        if re.match(ipv4_v2, address, re.IGNORECASE):
            result = True

    return result

def is_a_domain(domain):

    result = None
    if domain:
        if re.match(ipv4_v2, domain, re.IGNORECASE):
            result = True

    return result
