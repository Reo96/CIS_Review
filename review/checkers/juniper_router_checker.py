import re

juniper_router_rules = [
    # 1
    {
        "rule": "Set system hostname",
        "pass_patterns": [r"set\s+.*system\s+.*host-name\s+.*\s+.*", r"system\s+.*host-name\s+.*\s+.*"],
        "fail_patterns": [],
        "suggestion": "Use: set system host-name <name>"
    },
    # 2
    {
        "rule": "Enable SSH v2 only",
        "pass_patterns": [r"set\s+.*system\s+.*services\s+.*ssh\s+.*protocol-version\s+.*v2"],
        "fail_patterns": [r"protocol-version\s+.*v1", r"disable\s+.*ssh"],
        "suggestion": "Force SSHv2: set system services ssh protocol-version v2"
    },
    # 3
    {
        "rule": "Configure login retry attempts",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*retry-options\s+.*tries\s+.*\d+"],
        "fail_patterns": [r"set\s+.*system\s+.*login\s+.*retry-options\s+.*tries\s+.*0"],
        "suggestion": "Limit retries: set system login retry-options tries 3"
    },
    # 4
    {
        "rule": "Define super‑user login class",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*user\s+.*\s+.*\s+.*class\s+.*super-user"],
        "fail_patterns": [],
        "suggestion": "Assign super-user class: set system login user <name> class super-user"
    },
    # 5
    {
        "rule": "Disable Telnet (management)",
        "pass_patterns": [r"delete\s+.*system\s+.*services\s+.*telnet", r"telnet\s+.*disable"],
        "fail_patterns": [r"system\s+.*services\s+.*telnet"],
        "suggestion": "Disable Telnet: delete system services telnet"
    },
    # 6
    {
        "rule": "Disable HTTP web management",
        "pass_patterns": [r"delete\s+.*system\s+.*services\s+.*web-management\s+.*http"],
        "fail_patterns": [r"web-management\s+.*http"],
        "suggestion": "Disable HTTP: delete system services web-management http"
    },
    # 7
    {
        "rule": "Enable HTTPS on web management",
        "pass_patterns": [r"set\s+.*system\s+.*services\s+.*web-management\s+.*https"],
        "fail_patterns": [],
        "suggestion": "Enable HTTPS: set system services web-management https"
    },
    # 8
    {
        "rule": "Configure syslog file and level",
        "pass_patterns": [r"set\s+.*system\s+.*syslog\s+.*file\s+.*\s+.*\s+.*\s+.*\s+.*\s+.*"],
        "fail_patterns": [r"delete\s+.*system\s+.*syslog"],
        "suggestion": "Set syslog file/level: set system syslog file messages any warning"
    },
    # 9
    {
        "rule": "Set timezone to UTC",
        "pass_patterns": [r"set\s+.*system\s+.*time-zone\s+.*UTC"],
        "fail_patterns": [],
        "suggestion": "Use UTC: set system time-zone UTC"
    },
    # 10
    {
        "rule": "Configure NTP server",
        "pass_patterns": [r"set\s+.*system\s+.*ntp\s+.*server\s+.*\d+\.\d+\.\d+\.\d+"],
        "fail_patterns": [r"delete\s+.*system\s+.*ntp"],
        "suggestion": "Set NTP: set system ntp server 10.0.0.1"
    },
    # 11
    {
        "rule": "Assign IP to interface",
        "pass_patterns": [r"set\s+.*interfaces\s+.*\s+.*\s+.*unit\s+.*\d+\s+.*family\s+.*inet\s+.*address\s+.*\d+\.\d+\.\d+\.\d+/\d+"],
        "fail_patterns": [],
        "suggestion": "Assign IP: set interfaces ge-0/0/0 unit 0 family inet address x.x.x.x/yy"
    },
    # 12
    {
        "rule": "Deactivate unused interface",
        "pass_patterns": [r"deactivate\s+.*interfaces\s+.*\s+.*"],
        "fail_patterns": [r"activate\s+.*interfaces"],
        "suggestion": "Deactivate interface: deactivate interfaces ge-0/0/1"
    },
    # 13
    {
        "rule": "Set login banner message",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*message\s+.*\".*\""],
        "fail_patterns": [],
        "suggestion": "Define login message: set system login message \"Your banner here\""
    },
    # 14
    {
        "rule": "Enable firewall filter deny‑icmp",
        "pass_patterns": [r"filter\s+.*\s+.*\s+.*term\s+.*\s+.*\s+.*from\s+.*protocol\s+.*icmp"],
        "fail_patterns": [],
        "suggestion": "Add ICMP deny term: set firewall family inet filter <name> term deny-icmp from protocol icmp"
    },
    # 15
    {
        "rule": "Enable firewall filter deny‑fragment",
        "pass_patterns": [r"filter\s+.*\s+.*\s+.*term\s+.*\s+.*\s+.*from\s+.*is-fragment\s+.*true"],
        "fail_patterns": [],
        "suggestion": "Add frag deny term: set firewall family inet filter <name> term deny-frag from is-fragment true"
    },
    # 16
    {
        "rule": "Enable firewall filter default accept",
        "pass_patterns": [r"filter\s+.*\s+.*\s+.*term\s+.*\s+.*\s+.*then\s+.*accept"],
        "fail_patterns": [],
        "suggestion": "Add default accept term: set firewall family inet filter <name> term default then accept"
    },
    # 17
    {
        "rule": "Restrict SNMP v1/v2 community",
        "pass_patterns": [r"snmp\s+.*v3"],
        "fail_patterns": [r"snmp\s+.*community\s+.*public"],
        "suggestion": "Use SNMPv3 only and delete 'public' community"
    },
    # 18
    {
        "rule": "Configure AAA (TACACS+/RADIUS)",
        "pass_patterns": [r".*tacacs-server.*", r".*radius-server.*"],
        "fail_patterns": [],
        "suggestion": "Use external AAA: set system authentication-order [ radius tacacs ]"
    },
    # 19
    {
        "rule": "Enforce login accounting",
        "pass_patterns": [r"system\s+.*accounting"],
        "fail_patterns": [],
        "suggestion": "Enable accounting: set system accounting events login"
    },
    # 20
    {
        "rule": "Enforce config change archive",
        "pass_patterns": [r"commit\s+.*archive", r"record\s+.*configuration\s+.*changes"],
        "fail_patterns": [],
        "suggestion": "Archive commits: set system commit archive configuration"
    },
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    # Evaluate each rule
    for rule in juniper_router_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            text = line.lower()

            # Fail first
            for pat in rule["fail_patterns"]:
                if re.search(pat, text, re.IGNORECASE):
                    found_fail = True
                    matched_indices.add(idx)

            # Then pass
            for pat in rule["pass_patterns"]:
                if re.search(pat, text, re.IGNORECASE):
                    found_pass = True
                    matched_indices.add(idx)

        if found_fail:
            results.append((name, "Fail", suggestion))
        elif found_pass:
            results.append((name, "Pass", ""))
        else:
            results.append((name, "Missing", "No configuration provided for this rule."))

    # Catch any truly unrecognized lines
    for idx, raw in enumerate(normalized):
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        if idx not in matched_indices:
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
