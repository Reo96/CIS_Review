import re

juniper_firewall_rules = [
    {
        "rule": "Disable telnet for management",
        "pass_patterns": [r"delete\s+.*system\s+.*services\s+.*telnet", r"telnet\s+.*disable"],
        "fail_patterns": [r"system\s+.*services\s+.*telnet"],
        "suggestion": "Disable Telnet with: delete system services telnet"
    },
    {
        "rule": "Enable SSH for secure management",
        "pass_patterns": [r"system\s+.*services\s+.*ssh", r"set\s+.*system\s+.*services\s+.*ssh"],
        "fail_patterns": [],
        "suggestion": "Enable SSH with: set system services ssh"
    },
    {
        "rule": "Disable HTTP web access",
        "pass_patterns": [r"delete\s+.*system\s+.*services\s+.*web-management\s+.*http"],
        "fail_patterns": [r"web-management\s+.*http"],
        "suggestion": "Disable HTTP with: delete system services web-management http"
    },
    {
        "rule": "Enable HTTPS on web management",
        "pass_patterns": [r"web-management\s+.*https", r"set\s+.*system\s+.*services\s+.*web-management\s+.*https"],
        "fail_patterns": [],
        "suggestion": "Enable HTTPS with: set system services web-management https"
    },
    {
        "rule": "Configure syslog host",
        "pass_patterns": [r"system\s+.*syslog\s+.*host", r"set\s+.*system\s+.*syslog\s+.*host"],
        "fail_patterns": [],
        "suggestion": "Use: set system syslog host <IP>"
    },
    {
        "rule": "Use SNMPv3 and disable public community",
        "pass_patterns": [r"snmp\s+.*v3"],
        "fail_patterns": [r"snmp\s+.*community\s+.*public"],
        "suggestion": "Avoid SNMP v1/v2, remove default community: delete snmp community public"
    },
    {
        "rule": "Set NTP server",
        "pass_patterns": [r"set\s+.*system\s+.*ntp\s+.*server", r"system\s+.*ntp\s+.*server"],
        "fail_patterns": [],
        "suggestion": "Use: set system ntp server <IP>"
    },
    {
        "rule": "Configure login retry limit",
        "pass_patterns": [r"set\s+.*system\s+.*login\s+.*retry-options", r"login\s+.*retry-options"],
        "fail_patterns": [],
        "suggestion": "Limit login retries with: set system login retry-options retry-count X"
    },
    {
        "rule": "Enforce password policy",
        "pass_patterns": [r"password-policy", r"set\s+.*system\s+.*login\s+.*password-policy"],
        "fail_patterns": [],
        "suggestion": "Use password policies: set system login password-policy ..."
    },
    {
        "rule": "Set session inactivity timeout",
        "pass_patterns": [r"set\s+.*system\s+.*inactivity-timeout", r"inactivity-timeout"],
        "fail_patterns": [],
        "suggestion": "Set timeout: set system inactivity-timeout 10"
    },
    {
        "rule": "Restrict root login",
        "pass_patterns": [r"disable-root-login", r"root-authentication"],
        "fail_patterns": [],
        "suggestion": "Avoid root login or use root-authentication with SSH keys"
    },
    {
        "rule": "Enable accounting for logins",
        "pass_patterns": [r"system\s+.*accounting", r"set\s+.*system\s+.*accounting"],
        "fail_patterns": [],
        "suggestion": "Enable accounting logs for login actions"
    },
    {
        "rule": "Record configuration changes",
        "pass_patterns": [r"commit\s+.*archive", r"record\s+.*configuration\s+.*changes"],
        "fail_patterns": [],
        "suggestion": "Enable commit archive: set system commit archive"
    },
    {
        "rule": "Timezone should be UTC",
        "pass_patterns": [r"time-zone\s+.*UTC", r"set\s+.*system\s+.*time-zone\s+.*UTC"],
        "fail_patterns": [],
        "suggestion": "Set timezone to UTC"
    },
    {
        "rule": "Disable unused interfaces",
        "pass_patterns": [r"set\s+.*interfaces\s+.*\s+.*\s+.*disable"],
        "fail_patterns": [],
        "suggestion": "Disable unused interfaces: set interfaces <intf> disable"
    },
    {
        "rule": "Set hostname",
        "pass_patterns": [r"set\s+.*system\s+.*host-name", r"system\s+.*host-name"],
        "fail_patterns": [],
        "suggestion": "Use: set system host-name <name>"
    },
    {
        "rule": "Disable auto software upgrades",
        "pass_patterns": [r"auto-updates\s+.*disable"],
        "fail_patterns": [],
        "suggestion": "Turn off auto-updates: set system auto-updates disable"
    },
    {
        "rule": "Configure TACACS+ or RADIUS authentication",
        "pass_patterns": [r"radius-server", r"tacacs-server"],
        "fail_patterns": [],
        "suggestion": "Set up AAA: set system authentication-order [ radius tacacs ]"
    },
    {
        "rule": "Disable ICMP redirects",
        "pass_patterns": [r"icmp\s+.*redirect\s+.*disable", r"icmp-redirect.*disable", r"set\s+.*system\s+.*sysctl.*icmp_redirect.*0"],
        "fail_patterns": [r"icmp\s+.*redirect"],
        "suggestion": "Disable ICMP redirects: set system sysctl icmp_redirect 0"
    },
    {
        "rule": "Set max login attempts",
        "pass_patterns": [r"login\s+.*retry-options.*retry-count", r"set\s+.*system\s+.*login\s+.*retry-options.*retry-count"],
        "fail_patterns": [],
        "suggestion": "Limit failed logins: set system login retry-options retry-count 3"
    },
]

def check_rules(lines):
    results = []
    matched_lines = set()

    for rule in juniper_firewall_rules:
        rule_name = rule["rule"]
        passed = False
        failed = False

        for idx, line in enumerate(lines):
            line_lower = line.lower()
            # Check fail patterns first
            for pat in rule["fail_patterns"]:
                if re.search(pat, line_lower):
                    failed = True
                    matched_lines.add(idx)
                    break
            if failed:
                break  # no need to check pass patterns if failed

            # Check pass patterns
            for pat in rule["pass_patterns"]:
                if re.search(pat, line_lower):
                    passed = True
                    matched_lines.add(idx)
                    break
            if passed:
                break

        if failed:
            results.append((rule_name, "Fail", rule["suggestion"]))
        elif passed:
            results.append((rule_name, "Pass", "-"))
        else:
            results.append((rule_name, "Missing", rule["suggestion"]))

    # Detect unrecognized lines (those not matched by any pattern)
    known_patterns = [pat for rule in juniper_firewall_rules for pat in (rule["pass_patterns"] + rule["fail_patterns"])]
    for idx, line in enumerate(lines):
        if idx not in matched_lines:
            line_lower = line.lower()
            if not any(re.search(pat, line_lower) for pat in known_patterns):
                results.append((line.strip(), "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
