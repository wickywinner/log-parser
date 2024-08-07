import re

def parse_log(log_str):
    # Extract everything after "msg="
    msg_match = re.search(r"msg=(.*?)(?=\s\w+=|$)", log_str)
    
    if msg_match:
        msg_value = msg_match.group(1).replace("\\=", "=")
        log_str = log_str.replace(msg_match.group(0), "")
    else:
        msg_value = ""

    # Define the pattern to match key-value pairs in the log string
    pattern = r"(\w+)=([^ ]+)"
    
    # Find all matches in the log string
    matches = re.findall(pattern, log_str)
    
    # Create a dictionary from the matches
    log_dict = {key: value for key, value in matches}
    
    # Add the extracted msg value
    log_dict["msg"] = msg_value
    
    return log_dict

# Example log string
log_str = r"""SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"""

# Parse the log string and print the result
parsed_log = parse_log(log_str)
print(parsed_log)
