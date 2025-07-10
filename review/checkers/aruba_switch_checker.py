import re

# The full set of 20 Aruba switch rules, unchanged
aruba_switch_rules = [
    {
        "rule": "Disable Telnet",
        "pass_patterns": [r"no\s+.*telnet\s+.*server", r"disable\s+.*telnet"],
        "fail_patterns": [r"telnet\s+.*server\s+.*enable", r"enable\s+.*telnet"],
        "suggestion": "Disable Telnet using: no telnet server"
    },
    {
        "rule": "Enable SSH",
        "pass_patterns": [r"ssh\s+.*server\s+.*enable", r"enable\s+.*ssh"],
        "fail_patterns": [r"no\s+.*ssh\s+.*server", r"disable\s+.*ssh"],
        "suggestion": "Enable SSH using: ssh server enable"
    },
    {
        "rule": "Set login banner",
        "pass_patterns": [r"banner\s+.*login", r"banner\s+.*motd"],
        "fail_patterns": [r"no\s+.*banner\s+.*login", r"no\s+.*banner\s+.*motd"],
        "suggestion": "Set login banner using: banner login"
    },
    {
        "rule": "Configure password complexity",
        "pass_patterns": [r"password\s+.*minimum-length\s+.*\d+", r"password\s+.*complexity\s+.*enable"],
        "fail_patterns": [r"password\s+.*minimum-length\s+.*[1-5]\b", r"no\s+.*password\s+.*complexity"],
        "suggestion": "Use: password minimum-length 8 and enable complexity"
    },
    {
        "rule": "Disable unused ports",
        "pass_patterns": [r"shutdown\s+.*interface", r"disable\s+.*port"],
        "fail_patterns": [r"no\s+.*shutdown\s+.*interface", r"enable\s+.*port"],
        "suggestion": "Shutdown all unused interfaces"
    },
    {
        "rule": "Enable SNMPv3",
        "pass_patterns": [r"snmpv3\s+.*user", r"enable\s+.*snmpv3"],
        "fail_patterns": [r"snmp-server\s+.*community\s+.*public", r"enable\s+.*snmpv1", r"enable\s+.*snmpv2"],
        "suggestion": "Use SNMPv3 instead of SNMPv1/v2"
    },
    {
        "rule": "Restrict SNMP community",
        "pass_patterns": [r"no\s+.*snmp-server\s+.*community\s+.*public", r"snmp-server\s+.*community\s+.*restricted"],
        "fail_patterns": [r"snmp-server\s+.*community\s+.*public", r"snmp\s+.*community\s+.*public"],
        "suggestion": "Avoid using 'public' community strings"
    },
    {
        "rule": "Enable AAA",
        "pass_patterns": [r"aaa\s+.*authentication", r"aaa\s+.*authorization"],
        "fail_patterns": [r"no\s+.*aaa\s+.*authentication", r"no\s+.*aaa\s+.*authorization"],
        "suggestion": "Enable AAA authentication and authorization"
    },
    {
        "rule": "Enable syslog",
        "pass_patterns": [r"logging\s+.*host", r"logging\s+.*enable"],
        "fail_patterns": [r"no\s+.*logging\s+.*host", r"disable\s+.*syslog"],
        "suggestion": "Configure syslog using: logging host <ip>"
    },
    {
        "rule": "Configure NTP",
        "pass_patterns": [r"ntp\s+.*server", r"ntp\s+.*enable"],
        "fail_patterns": [r"no\s+.*ntp\s+.*server", r"disable\s+.*ntp"],
        "suggestion": "Use NTP for clock synchronization"
    },
    {
        "rule": "Disable HTTP server",
        "pass_patterns": [r"no\s+.*web-management\s+.*http", r"disable\s+.*http"],
        "fail_patterns": [r"web-management\s+.*http", r"enable\s+.*http"],
        "suggestion": "Disable HTTP and use HTTPS"
    },
    {
        "rule": "Enable HTTPS",
        "pass_patterns": [r"web-management\s+.*ssl", r"https\s+.*enable"],
        "fail_patterns": [r"no\s+.*https", r"disable\s+.*https"],
        "suggestion": "Enable secure HTTPS management"
    },
    {
        "rule": "Use RADIUS",
        "pass_patterns": [r"radius-server", r"aaa\s+.*authentication\s+.*login\s+.*radius"],
        "fail_patterns": [r"no\s+.*radius-server", r"disable\s+.*radius"],
        "suggestion": "Enable RADIUS for authentication"
    },
    {
        "rule": "Set session timeout",
        "pass_patterns": [r"console\s+.*inactivity-timer", r"session-timeout"],
        "fail_patterns": [r"no\s+.*console\s+.*inactivity-timer", r"no\s+.*session-timeout"],
        "suggestion": "Set inactivity timeout to auto log out users"
    },
    {
        "rule": "Enable storm control",
        "pass_patterns": [r"storm-control", r"enable\s+.*storm\s+.*control"],
        "fail_patterns": [r"no\s+.*storm-control", r"disable\s+.*storm"],
        "suggestion": "Prevent traffic floods using storm control"
    },
    {
        "rule": "Enable BPDU protection",
        "pass_patterns": [r"spanning-tree\s+.*bpdu-protection", r"bpdu\s+.*guard"],
        "fail_patterns": [r"no\s+.*spanning-tree\s+.*bpdu-protection", r"disable\s+.*bpdu"],
        "suggestion": "Protect STP using BPDU guard"
    },
    {
        "rule": "Enable port security",
        "pass_patterns": [r"port-security\s+.*enable", r"mac-address\s+.*limit"],
        "fail_patterns": [r"no\s+.*port-security", r"unlimited\s+.*mac-address"],
        "suggestion": "Restrict number of MACs on a port"
    },
    {
        "rule": "Disable unused VLANs",
        "pass_patterns": [r"no\s+.*vlan\s+.*\d+\s+.*active", r"disable\s+.*vlan"],
        "fail_patterns": [r"vlan\s+.*\d+\s+.*active", r"enable\s+.*vlan"],
        "suggestion": "Deactivate unused VLANs"
    },
    {
        "rule": "Set hostname",
        "pass_patterns": [r"hostname\s+.*\s+.*", r"system-name\s+.*\s+.*"],
        "fail_patterns": [r"hostname\s+.*default", r"system-name\s+.*default"],
        "suggestion": "Set hostname for easier management"
    },
    {
        "rule": "Enable interface description",
        "pass_patterns": [r"description\s+.*\s+.*", r"interface\s+.*\s+.*\s+.*description"],
        "fail_patterns": [r"no\s+.*description", r"interface\s+.*\s+.*\s+.*no\s+.*description"],
        "suggestion": "Use interface descriptions for clarity"
    },
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    # 1) Evaluate each rule
    for rule in aruba_switch_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('!') or line.startswith('#'):
                continue
            text = line.lower()

            # Check fail first (so a bad config is always flagged)
            for pat in rule["fail_patterns"]:
                if re.search(pat, text):
                    found_fail = True
                    matched_indices.add(idx)
            # Then check pass
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

    # 2) Detect Unknown lines
    for idx, raw in enumerate(normalized):
        line = raw.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
        if idx not in matched_indices:
            results.append((line, "Unknown", "No matching benchmark rule for this configuration."))

    return results
