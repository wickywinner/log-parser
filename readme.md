# Log Parser

## Overview

This script parses a specific format of system logs generated by an antivirus program. The logs contain various fields and values, and the script extracts these into a structured dictionary for easier analysis and usage.

## Features

- Parses a given log string
- Extracts key-value pairs
- Handles special cases, such as messages containing escaped characters
- Outputs the result as a dictionary

## Requirements

- Python 3.x

## Usage

### Installation

1. Ensure you have Python 3 installed on your machine. You can download it from [python.org](https://www.python.org/downloads/).

2. Clone this repository (https://github.com/wickywinner/log-parser.git)or download the script file.

### Running the Script

1. Save the script as `log_parser.py`.

2. Open a terminal or command prompt.

3. Navigate to the directory where `log_parser.py` is saved.

4. Run the script using the following command:
    ```bash
    python log_parser.py
    ```

### Script Content

Here's the content of `log_parser.py`:

```python
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
    
    # Final dictionary formatted as required
    final_dict = {
        "cat": log_dict.get("cat"),
        "cs1Label": log_dict.get("cs1Label"),
        "cs1": log_dict.get("cs1"),
        "cs2Label": log_dict.get("cs2Label"),
        "cs2": log_dict.get("cs2"),
        "cs3Label": log_dict.get("cs3Label"),
        "cs3": log_dict.get("cs3"),
        "cs4Label": log_dict.get("cs4Label"),
        "cs4": log_dict.get("cs4"),
        "cn1Label": log_dict.get("cn1Label"),
        "cn1": log_dict.get("cn1"),
        "msg": log_dict.get("msg"),
        "dhost": log_dict.get("dhost"),
        "dst": log_dict.get("dst"),
    }
    
    return final_dict

# Example log string
log_str = r"""SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"""

# Parse the log string and print the dict result
parsed_log = parse_log(log_str)
print(parsed_log)
