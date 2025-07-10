import re

juniper_switch_rules = [
    {
        "rule": "Disable Telnet access",
        "pass_patterns": [r"delete\s+.*system\s+.*services\s+.*telnet"],
        "fail_patterns": [r"set\s+.*system\s+.*services\s+.*telnet"],
        "suggestion": "Disable Telnet using: delete system services telnet"
    },
    {
        "rule": "Enable SSH",
        "pass_patterns": [r"set\s+.*system\s+.*services\s+.*ssh"],
        "fail_patterns": [],
        "suggestion": "Enable SSH using: set system services ssh"
    },
    {
        "rule": "Set login banner",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*message"],
        "fail_patterns": [],
        "suggestion": "Set login message using: set system login message"
    },
    {
        "rule": "Set password complexity",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*password\s+.*format"],
        "fail_patterns": [],
        "suggestion": "Configure password complexity"
    },
    {
        "rule": "Set authentication retries",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*retry-options"],
        "fail_patterns": [],
        "suggestion": "Limit login retries using: set system login retry-options"
    },
    {
        "rule": "Disable root login",
        "pass_patterns": [r"delete\s+.*system\s+.*root-authentication"],
        "fail_patterns": [r"set\s+.*system\s+.*root-authentication"],
        "suggestion": "Disable root login using: delete system root-authentication"
    },
    {
        "rule": "Enable syslog",
        "pass_patterns": [r"set\s+.*system\s+.*syslog"],
        "fail_patterns": [],
        "suggestion": "Enable syslog with: set system syslog host <ip> any info"
    },
    {
        "rule": "Set NTP server",
        "pass_patterns": [r"set\s+.*system\s+.*ntp\s+.*server"],
        "fail_patterns": [],
        "suggestion": "Configure NTP using: set system ntp server <ip>"
    },
    {
        "rule": "Enable authentication order",
        "pass_patterns": [r"set\s+.*system\s+.*authentication-order"],
        "fail_patterns": [],
        "suggestion": "Set authentication order using: set system authentication-order [password radius]"
    },
    {
        "rule": "Enable interface descriptions",
        "pass_patterns": [r"set\s+.*interfaces\s+.*\s+.*\s+.*description"],
        "fail_patterns": [],
        "suggestion": "Add interface descriptions to document network"
    },
    {
        "rule": "Enable loop protect",
        "pass_patterns": [r"set\s+.*protocols\s+.*rstp"],
        "fail_patterns": [],
        "suggestion": "Enable loop protection with RSTP or similar"
    },
    {
        "rule": "Enable BPDU protection",
        "pass_patterns": [r"set\s+.*ethernet-switching-options\s+.*bpdu-block"],
        "fail_patterns": [],
        "suggestion": "Block BPDU packets on access ports"
    },
    {
        "rule": "Limit MAC addresses per port",
        "pass_patterns": [r"set\s+.*ethernet-switching-options\s+.*secure-access-port"],
        "fail_patterns": [],
        "suggestion": "Limit MACs using: set ethernet-switching-options secure-access-port"
    },
    {
        "rule": "Enable storm control",
        "pass_patterns": [r"set\s+.*ethernet-switching-options\s+.*storm-control"],
        "fail_patterns": [],
        "suggestion": "Prevent broadcast storms using storm control"
    },
    {
        "rule": "Set SNMP community",
        "pass_patterns": [r"set\s+.*snmp\s+.*community"],
        "fail_patterns": [],
        "suggestion": "Set SNMP community string and restrict access"
    },
    {
        "rule": "Disable LLDP on unused interfaces",
        "pass_patterns": [r"delete\s+.*protocols\s+.*lldp\s+.*interface"],
        "fail_patterns": [r"set\s+.*protocols\s+.*lldp\s+.*interface"],
        "suggestion": "Disable LLDP on unused interfaces"
    },
    {
        "rule": "Disable J-Web (web UI)",
        "pass_patterns": [r"delete\s+.*system\s+.*services\s+.*web-management"],
        "fail_patterns": [r"set\s+.*system\s+.*services\s+.*web-management"],
        "suggestion": "Disable web-management interface using: delete system services web-management"
    },
    {
        "rule": "Enable RADIUS authentication",
        "pass_patterns": [r"set\s+.*system\s+.*radius-server"],
        "fail_patterns": [],
        "suggestion": "Configure RADIUS using: set system radius-server <ip>"
    },
    {
        "rule": "Enable interface shutdown by default",
        "pass_patterns": [r"disable", r"interface\s+.*shutdown"],
        "fail_patterns": [],
        "suggestion": "Disable unused interfaces by default"
    },
    {
        "rule": "Enable accounting",
        "pass_patterns": [r"set\s+.*system\s+.*accounting"],
        "fail_patterns": [],
        "suggestion": "Enable system accounting for user actions"
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in juniper_switch_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            text = line.lower()

            for pat in rule["fail_patterns"]:
                if re.search(pat, text):
                    found_fail = True
                    matched_indices.add(idx)
                    break
            if found_fail:
                break

            for pat in rule["pass_patterns"]:
                if re.search(pat, text):
                    found_pass = True
                    matched_indices.add(idx)
                    break
            if found_pass:
                break

        if found_fail:
            results.append((name, "Fail", suggestion))
        elif found_pass:
            results.append((name, "Pass", ""))
        else:
            results.append((name, "Missing", suggestion))

    # Handle unmatched configs
    all_patterns = [pat for r in juniper_switch_rules for pat in (r["pass_patterns"] + r["fail_patterns"])]
    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
