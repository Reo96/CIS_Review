import re

# Define benchmark rules
cisco_router_rules = [
    {
        "rule": "Disable Telnet access",
        "pass_patterns": [
            r"transport\s+.*input\s+.*ssh",
            r"line\s+.*vty.*\n.*transport\s+.*input\s+.*ssh"
        ],
        "fail_patterns": [
            r"transport\s+.*input\s+.*telnet",
            r"line\s+.*vty.*\n.*transport\s+.*input\s+.*telnet"
        ],
        "suggestion": "Disable Telnet by allowing only SSH using: transport input ssh"
    },
    {
        "rule": "Enable SSH version 2",
        "pass_patterns": [r"ip\s+.*ssh\s+.*version\s+.*2"],
        "fail_patterns": [r"ip\s+.*ssh\s+.*version\s+.*[01]"],
        "suggestion": "Enable SSH v2 with: ip ssh version 2"
    },
    {
        "rule": "Set login banner",
        "pass_patterns": [r"banner\s+.*login", r"banner\s+.*motd"],
        "fail_patterns": [r"no\s+.*banner\s+.*login", r"no\s+.*banner\s+.*motd"],
        "suggestion": "Use: banner login to set a warning banner"
    },
    {
        "rule": "Set strong password encryption",
        "pass_patterns": [r"service\s+.*password-encryption"],
        "fail_patterns": [r"no\s+.*service\s+.*password-encryption"],
        "suggestion": "Use: service password-encryption to encrypt plain text passwords"
    },
    {
        "rule": "Enable password complexity",
        "pass_patterns": [r"security\s+.*password\s+.*min-length", r"password\s+.*policy"],
        "fail_patterns": [r"min-length\s+.*[1-5]", r"no\s+.*password\s+.*policy"],
        "suggestion": "Set password complexity and min length (e.g., 10+)"
    },
    {
        "rule": "Enable logging",
        "pass_patterns": [r"logging\s+.*buffered", r"logging\s+.*host"],
        "fail_patterns": [r"no\s+.*logging"],
        "suggestion": "Enable logging using: logging buffered or logging host"
    },
    {
        "rule": "Set NTP server",
        "pass_patterns": [r"ntp\s+.*server", r"ntp\s+.*peer"],
        "fail_patterns": [r"no\s+.*ntp\s+.*server", r"disable\s+.*ntp"],
        "suggestion": "Use NTP for accurate time sync"
    },
    {
        "rule": "Set exec timeout",
        "pass_patterns": [r"exec-timeout\s+.*\d+", r"line\s+.*console.*\n.*exec-timeout"],
        "fail_patterns": [r"exec-timeout\s+.*0", r"no\s+.*exec-timeout"],
        "suggestion": "Use: exec-timeout 5 to limit idle sessions"
    },
    {
        "rule": "Disable unused interfaces",
        "pass_patterns": [r"interface\s+.*\s+.*\n\s*shutdown", r"shutdown\s+.*interface"],
        "fail_patterns": [r"no\s+.*shutdown"],
        "suggestion": "Shutdown all unused interfaces"
    },
    {
        "rule": "Use AAA authentication",
        "pass_patterns": [r"aaa\s+.*new-model", r"aaa\s+.*authentication\s+.*login"],
        "fail_patterns": [r"no\s+.*aaa\s+.*new-model"],
        "suggestion": "Use AAA for authentication"
    },
    {
        "rule": "Enable role-based CLI views",
        "pass_patterns": [r"parser\s+.*view", r"enable\s+.*view"],
        "fail_patterns": [r"no\s+.*parser\s+.*view"],
        "suggestion": "Use parser views to limit CLI access"
    },
    {
        "rule": "Disable HTTP server",
        "pass_patterns": [r"no\s+.*ip\s+.*http\s+.*server"],
        "fail_patterns": [r"ip\s+.*http\s+.*server"],
        "suggestion": "Disable HTTP server using: no ip http server"
    },
    {
        "rule": "Enable HTTPS server",
        "pass_patterns": [r"ip\s+.*http\s+.*secure-server"],
        "fail_patterns": [r"no\s+.*ip\s+.*http\s+.*secure-server"],
        "suggestion": "Enable HTTPS with: ip http secure-server"
    },
    {
        "rule": "Restrict SNMP community",
        "pass_patterns": [r"snmp-server\s+.*community\s+.*\s+.*\s+.*(RO|RW)", r"no\s+.*snmp-server\s+.*community\s+.*public"],
        "fail_patterns": [r"snmp-server\s+.*community\s+.*public"],
        "suggestion": "Avoid default/public SNMP communities"
    },
    {
        "rule": "Enable SNMPv3",
        "pass_patterns": [r"snmp-server\s+.*group.*v3", r"snmp-server\s+.*user.*v3"],
        "fail_patterns": [r"snmp-server\s+.*group.*v1", r"snmp-server\s+.*user.*v2"],
        "suggestion": "Use SNMPv3 with groups and users"
    },
    {
        "rule": "Enable port security",
        "pass_patterns": [r"switchport\s+.*port-security", r"port-security\s+.*maximum"],
        "fail_patterns": [r"no\s+.*port-security"],
        "suggestion": "Enable port-security on user-facing ports"
    },
    {
        "rule": "Enable control plane protection",
        "pass_patterns": [r"control-plane", r"copp\s+.*policy"],
        "fail_patterns": [r"no\s+.*control-plane"],
        "suggestion": "Protect control plane using CoPP"
    },
    {
        "rule": "Enable storm control",
        "pass_patterns": [r"storm-control\s+.*broadcast", r"storm-control\s+.*multicast"],
        "fail_patterns": [r"no\s+.*storm-control"],
        "suggestion": "Use storm control to prevent broadcast storms"
    },
    {
        "rule": "Disable CDP",
        "pass_patterns": [r"no\s+.*cdp\s+.*run", r"interface\s+.*\s+.*.*\n.*no\s+.*cdp\s+.*enable"],
        "fail_patterns": [r"cdp\s+.*enable"],
        "suggestion": "Disable CDP globally or per interface"
    },
    {
        "rule": "Disable LLDP",
        "pass_patterns": [r"no\s+.*lldp\s+.*run", r"interface\s+.*\s+.*.*\n.*no\s+.*lldp\s+.*transmit"],
        "fail_patterns": [r"lldp\s+.*run"],
        "suggestion": "Disable LLDP on access interfaces"
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in cisco_router_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                continue
            text = line.lower()

            for pat in rule["fail_patterns"]:
                if re.search(pat, text):
                    found_fail = True
                    matched_indices.add(idx)

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

    # Unknown config lines
    for idx, raw in enumerate(normalized):
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if idx not in matched_indices:
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
