import re

extreme_switch_rules = [
    {
        "rule": "Disable Telnet",
        "pass_patterns": [r"disable\s+.*telnet", r"configure\s+.*telnet\s+.*disable"],
        "fail_patterns": [r"enable\s+.*telnet", r"telnet\s+.*enable"],
        "suggestion": "Disable Telnet using: disable telnet or configure telnet disable"
    },
    {
        "rule": "Enable SSH",
        "pass_patterns": [r"enable\s+.*ssh", r"configure\s+.*ssh\s+.*enable"],
        "fail_patterns": [r"disable\s+.*ssh"],
        "suggestion": "Enable SSH using: enable ssh"
    },
    {
        "rule": "Set login banner",
        "pass_patterns": [r"configure\s+.*banner\s+.*login", r"banner\s+.*login"],
        "fail_patterns": [r"no\s+.*banner\s+.*login"],
        "suggestion": "Set login banner using: configure banner login"
    },
    {
        "rule": "Set password complexity",
        "pass_patterns": [r"enable\s+.*password\s+.*complexity", r"password\s+.*minimum-length", r"password\s+.*require"],
        "fail_patterns": [],
        "suggestion": "Use: enable password complexity and set minimum-length"
    },
    {
        "rule": "Disable unused ports",
        "pass_patterns": [r"disable\s+.*ports", r"configure\s+.*ports\s+.*\s+.*\s+.*disable"],
        "fail_patterns": [],
        "suggestion": "Disable all unused ports"
    },
    {
        "rule": "Enable SNMPv3",
        "pass_patterns": [r"enable\s+.*snmpv3", r"snmpv3\s+.*user"],
        "fail_patterns": [r"snmp\s+.*community\s+.*public", r"snmp\s+.*community\s+.*private"],
        "suggestion": "Use SNMPv3 for secure network management"
    },
    {
        "rule": "Restrict SNMP community",
        "pass_patterns": [r"disable\s+.*snmp\s+.*community", r"snmp\s+.*community\s+.*read-only"],
        "fail_patterns": [r"snmp\s+.*community\s+.*public", r"community\s+.*read-write"],
        "suggestion": "Avoid public SNMP community strings"
    },
    {
        "rule": "Enable AAA",
        "pass_patterns": [r"enable\s+.*aaa", r"configure\s+.*aaa"],
        "fail_patterns": [],
        "suggestion": "Enable AAA for secure authentication"
    },
    {
        "rule": "Enable logging",
        "pass_patterns": [r"enable\s+.*logging", r"configure\s+.*log"],
        "fail_patterns": [],
        "suggestion": "Enable logging for system monitoring"
    },
    {
        "rule": "Set NTP server",
        "pass_patterns": [r"configure\s+.*ntp\s+.*server", r"ntp\s+.*server"],
        "fail_patterns": [],
        "suggestion": "Use NTP server for time synchronization"
    },
    {
        "rule": "Disable HTTP management",
        "pass_patterns": [r"disable\s+.*web", r"disable\s+.*http"],
        "fail_patterns": [r"enable\s+.*web", r"http\s+.*enable"],
        "suggestion": "Disable HTTP and use HTTPS only"
    },
    {
        "rule": "Enable HTTPS",
        "pass_patterns": [r"enable\s+.*https", r"configure\s+.*https\s+.*secure"],
        "fail_patterns": [],
        "suggestion": "Enable secure web management"
    },
    {
        "rule": "Enable RADIUS authentication",
        "pass_patterns": [r"configure\s+.*radius\s+.*server", r"enable\s+.*radius"],
        "fail_patterns": [],
        "suggestion": "Use RADIUS for centralized authentication"
    },
    {
        "rule": "Set inactivity timeout",
        "pass_patterns": [r"configure\s+.*idle-timeout", r"set\s+.*session-timeout"],
        "fail_patterns": [],
        "suggestion": "Use: configure idle-timeout <minutes>"
    },
    {
        "rule": "Enable loop protection",
        "pass_patterns": [r"enable\s+.*loop-protect", r"configure\s+.*loop-detection"],
        "fail_patterns": [],
        "suggestion": "Enable loop-protect to prevent broadcast storms"
    },
    {
        "rule": "Enable storm control",
        "pass_patterns": [r"enable\s+.*storm-control", r"configure\s+.*storm-control"],
        "fail_patterns": [],
        "suggestion": "Limit traffic storms on interfaces"
    },
    {
        "rule": "Use secure STP settings",
        "pass_patterns": [r"enable\s+.*stp", r"configure\s+.*spanning-tree"],
        "fail_patterns": [],
        "suggestion": "Ensure secure STP configuration"
    },
    {
        "rule": "Enable port security",
        "pass_patterns": [r"enable\s+.*port-security", r"configure\s+.*mac\s+.*locking"],
        "fail_patterns": [],
        "suggestion": "Restrict MAC addresses on ports"
    },
    {
        "rule": "Disable CDP or LLDP",
        "pass_patterns": [r"disable\s+.*cdp", r"disable\s+.*lldp"],
        "fail_patterns": [r"enable\s+.*cdp", r"enable\s+.*lldp"],
        "suggestion": "Disable unnecessary discovery protocols"
    },
    {
        "rule": "Secure SNMP trap settings",
        "pass_patterns": [r"snmp\s+.*trap\s+.*authentication", r"configure\s+.*snmp\s+.*trap"],
        "fail_patterns": [],
        "suggestion": "Secure SNMP traps to prevent data leaks"
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    # 1) Evaluate each rule
    for rule in extreme_switch_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            text = line.lower()

            # Check fail patterns first (strict negatives)
            for pat in rule["fail_patterns"]:
                if re.search(pat, text):
                    found_fail = True
                    matched_indices.add(idx)

            # Then check pass patterns
            for pat in rule["pass_patterns"]:
                if re.search(pat, text):
                    found_pass = True
                    matched_indices.add(idx)

        if found_fail:
            results.append((name, "Fail", suggestion))
        elif found_pass:
            results.append((name, "Pass", ""))
        else:
            results.append((name, "Missing", "No configuration provided for this rule."))

    # 2) Detect unknown config lines
    for idx, raw in enumerate(normalized):
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        if idx not in matched_indices:
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
