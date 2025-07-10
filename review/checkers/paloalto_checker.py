import re

paloalto_rules = [
    {
        "rule": "Enable SCP for secure file transfer",
        "pass_patterns": [
            r"\bscp\s+.*enable\b",
            r"\bset\s+.*ssh\s+.*scp\s+.*enable\b"
        ],
        "fail_patterns": [
            r"\bscp\s+.*disable\b",
            r"\bset\s+.*ssh\s+.*scp\s+.*disable\b"
        ],
        "suggestion": "Enable SCP using 'set ssh scp enable'."
    },
    {
        "rule": "Use strong admin passwords",
        "pass_patterns": [
            r"\bpassword\s+.*complexity\b",
            r"\badmin\s+.*password\s+.*profile\b",
            r"\bpassword\s+.*profile\s+.*enforce\b"
        ],
        "fail_patterns": [
            r"\bpassword\s+.*complexity\s+.*disable\b",
            r"\bpassword\s+.*profile\s+.*disable\b"
        ],
        "suggestion": "Enable password complexity with 'set password profile enforce'."
    },
    {
        "rule": "Enable NTP configuration",
        "pass_patterns": [
            r"\bset\s+.*ntp\b",
            r"\bntp\s+.*servers\b",
            r"\bntp\s+.*primary\b"
        ],
        "fail_patterns": [
            r"\bntp\s+.*disable\b",
            r"\bno\s+.*ntp\b"
        ],
        "suggestion": "Set NTP servers using 'set deviceconfig system ntp-servers <ip>'."
    },
    {
        "rule": "Enable log forwarding",
        "pass_patterns": [
            r"\blog\s+.*forwarding\b",
            r"\bset\s+.*log\s+.*settings\b",
            r"\bforward\s+.*logs\b"
        ],
        "fail_patterns": [
            r"\blog\s+.*forwarding\s+.*disable\b",
            r"\bno\s+.*log\s+.*forwarding\b"
        ],
        "suggestion": "Configure log forwarding for better monitoring."
    },
    {
        "rule": "Disable telnet access",
        "pass_patterns": [
            r"\btelnet\s+.*disable\b",
            r"\bset\s+.*telnet\s+.*off\b",
            r"\bno\s+.*telnet\b"
        ],
        "fail_patterns": [
            r"\btelnet\s+.*enable\b",
            r"\bset\s+.*telnet\s+.*on\b"
        ],
        "suggestion": "Disable telnet for improved security."
    },
    {
        "rule": "Enable SSH service",
        "pass_patterns": [
            r"\bssh\s+.*enable\b",
            r"\bset\s+.*ssh\s+.*service\b",
            r"\benable\s+.*ssh\b"
        ],
        "fail_patterns": [
            r"\bssh\s+.*disable\b",
            r"\bset\s+.*ssh\s+.*service\s+.*disable\b"
        ],
        "suggestion": "Enable SSH via 'set service ssh enable'."
    },
    {
        "rule": "Enable HTTPS access",
        "pass_patterns": [
            r"\bhttps\s+.*enable\b",
            r"\bweb\s+.*service\s+.*https\b",
            r"\badmin\s+.*https\s+.*enable\b"
        ],
        "fail_patterns": [
            r"\bhttps\s+.*disable\b",
            r"\bno\s+.*https\b"
        ],
        "suggestion": "Enable HTTPS access for secure UI login."
    },
    {
        "rule": "Configure management interface IP",
        "pass_patterns": [
            r"\bset\s+.*interface\s+.*mgmt\b",
            r"\bmgmt\s+.*ip\b",
            r"\bmanagement\s+.*interface\s+.*ip\b"
        ],
        "fail_patterns": [],
        "suggestion": "Configure a secure IP for management access."
    },
    {
        "rule": "Enable threat log",
        "pass_patterns": [
            r"\bset\s+.*log\s+.*threat\b",
            r"\bthreat\s+.*logging\b",
            r"\blog\s+.*threat\b"
        ],
        "fail_patterns": [
            r"\bthreat\s+.*logging\s+.*disable\b"
        ],
        "suggestion": "Enable threat logging to monitor malicious activities."
    },
    {
        "rule": "Enable WildFire submissions",
        "pass_patterns": [
            r"\bwildfire\s+.*submit\b",
            r"\bset\s+.*wildfire\b",
            r"\benable\s+.*wildfire\b"
        ],
        "fail_patterns": [
            r"\bwildfire\s+.*disable\b"
        ],
        "suggestion": "Enable WildFire to detect zero-day threats."
    },
    {
        "rule": "Set up DNS servers",
        "pass_patterns": [
            r"\bset\s+.*dns\b",
            r"\bdns\s+.*primary\b",
            r"\bdns\s+.*server\b"
        ],
        "fail_patterns": [],
        "suggestion": "Set up secure DNS servers."
    },
    {
        "rule": "Set login banner",
        "pass_patterns": [
            r"\bset\s+.*login-banner\b",
            r"\blogin\s+.*banner\b",
            r"\bbanner\s+.*set\b"
        ],
        "fail_patterns": [
            r"\bno\s+.*login-banner\b"
        ],
        "suggestion": "Set a login banner to show warning/legal messages."
    },
    {
        "rule": "Enable zone protection profiles",
        "pass_patterns": [
            r"\bzone-protection\b",
            r"\bset\s+.*zone\s+.*protection\b",
            r"\benable\s+.*zone\s+.*security\b"
        ],
        "fail_patterns": [
            r"\bzone-protection\s+.*disable\b"
        ],
        "suggestion": "Apply zone protection profiles for security."
    },
    {
        "rule": "Enable DoS protection",
        "pass_patterns": [
            r"\bset\s+.*dos\s+.*profile\b",
            r"\bdos\s+.*protect\b",
            r"\benable\s+.*dos\b"
        ],
        "fail_patterns": [
            r"\bdos\s+.*disable\b"
        ],
        "suggestion": "Enable DoS profiles for zones."
    },
    {
        "rule": "Enable interface management profile",
        "pass_patterns": [
            r"\bset\s+.*interface\s+.*mgmt-profile\b",
            r"\binterface\s+.*profile\b",
            r"\bmgmt\s+.*profile\s+.*enable\b"
        ],
        "fail_patterns": [],
        "suggestion": "Assign a management profile to interfaces."
    },
    {
        "rule": "Set admin idle timeout",
        "pass_patterns": [
            r"\bidle-timeout\b",
            r"\badmin\s+.*timeout\b",
            r"\bset\s+.*admin\s+.*idle\b"
        ],
        "fail_patterns": [],
        "suggestion": "Set idle timeout for admin sessions."
    },
    {
        "rule": "Set password expiration policy",
        "pass_patterns": [
            r"\bpassword\s+.*expiration\b",
            r"\bexpire\s+.*admin\s+.*password\b",
            r"\bset\s+.*password\s+.*expiry\b"
        ],
        "fail_patterns": [],
        "suggestion": "Set a password expiration duration for accounts."
    },
    {
        "rule": "Enable file blocking profiles",
        "pass_patterns": [
            r"\bfile-blocking\b",
            r"\bset\s+.*profile\s+.*file\b",
            r"\bblock\s+.*files\b"
        ],
        "fail_patterns": [],
        "suggestion": "Enable file blocking for risky file types."
    },
    {
        "rule": "Enable antivirus profiles",
        "pass_patterns": [
            r"\bantivirus\b",
            r"\bset\s+.*profile\s+.*av\b",
            r"\bav\s+.*profile\b"
        ],
        "fail_patterns": [],
        "suggestion": "Use antivirus security profiles for traffic."
    },
    {
        "rule": "Enable URL filtering",
        "pass_patterns": [
            r"\burl\s+.*filtering\b",
            r"\bset\s+.*url\s+.*profile\b",
            r"\bfilter\s+.*urls\b"
        ],
        "fail_patterns": [],
        "suggestion": "Enable URL filtering to block malicious websites."
    },
    {
        "rule": "Disable HTTP service",
        "pass_patterns": [
            r"\bset\s+.*deviceconfig\s+.*system\s+.*service\s+.*disable-http\s+.*yes\b",
            r"\bhttp\s+.*disable\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*deviceconfig\s+.*system\s+.*service\s+.*disable-http\s+.*no\b",
            r"\bhttp\s+.*enable\b"
        ],
        "suggestion": "Disable HTTP service using 'set deviceconfig system service disable-http yes'."
    },
    {
        "rule": "Set max login attempts",
        "pass_patterns": [
            r"\bset\s+.*deviceconfig\s+.*system\s+.*max-login-attempts\s+.*\d+\b"
        ],
        "fail_patterns": [],
        "suggestion": "Set max login attempts using 'set deviceconfig system max-login-attempts <number>'."
    },
    {
        "rule": "Password profile complexity requirements",
        "pass_patterns": [
            r"\bset\s+.*password-profile\s+.*\s+.*\s+.*lower-case\s+.*yes\b",
            r"\bset\s+.*password-profile\s+.*\s+.*\s+.*upper-case\s+.*yes\b",
            r"\bset\s+.*password-profile\s+.*\s+.*\s+.*number\s+.*yes\b"
        ],
        "fail_patterns": [
            r"\blower-case\s+.*no\b",
            r"\bupper-case\s+.*no\b",
            r"\bnumber\s+.*no\b"
        ],
        "suggestion": "Ensure password profile enforces complexity with lower-case, upper-case, and number set to yes."
    },
    {
        "rule": "Configure NTP servers",
        "pass_patterns": [
            r"\bset\s+.*deviceconfig\s+.*system\s+.*ntp-servers\s+.*[\d\.]+\b"
        ],
        "fail_patterns": [],
        "suggestion": "Configure NTP servers using 'set deviceconfig system ntp-servers <ip>'."
    },
    {
        "rule": "SNMPv3 user configuration",
        "pass_patterns": [
            r"\bsnmpv3\s+.*user\s+.*\s+.*\s+.*authentication\s+.*\s+.*\s+.*\s+.*\s+.*privacy\s+.*\s+.*\s+.*\s+.*\b"
        ],
        "fail_patterns": [],
        "suggestion": "Configure SNMPv3 users with authentication and privacy settings."
    },
    {
        "rule": "Syslog server configuration",
        "pass_patterns": [
            r"\bset\s+.*log-settings\s+.*syslog\s+.*\s+.*\s+.*server\s+.*[\d\.]+\b"
        ],
        "fail_patterns": [],
        "suggestion": "Configure syslog server using 'set log-settings syslog <name> server <ip>'."
    },
    {
        "rule": "Assign admin role to user",
        "pass_patterns": [
            r"\bset\s+.*mgt-config\s+.*users\s+.*\s+.*\s+.*role\s+.*\s+.*\b"
        ],
        "fail_patterns": [],
        "suggestion": "Assign admin roles using 'set mgt-config users <username> role <role>'."
    },
    {
        "rule": "Enable two-factor authentication",
        "pass_patterns": [
            r"\bset\s+.*authentication-profile\s+.*\s+.*\s+.*two-factor\s+.*yes\b"
        ],
        "fail_patterns": [
            r"\btwo-factor\s+.*no\b"
        ],
        "suggestion": "Enable two-factor authentication using 'set authentication-profile <profile> two-factor yes'."
    },
    {
        "rule": "Disable ping service",
        "pass_patterns": [
            r"\bset\s+.*deviceconfig\s+.*system\s+.*service\s+.*disable-ping\s+.*yes\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*deviceconfig\s+.*system\s+.*service\s+.*disable-ping\s+.*no\b"
        ],
        "suggestion": "Disable ping service using 'set deviceconfig system service disable-ping yes'."
    }
]

def check_rules(config_lines):
    results = []
    matched = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    # Evaluate each Palo Alto rule
    for rule in paloalto_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        did_pass = False
        did_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            text = line.lower()

            # Fail patterns first
            for pat in rule["fail_patterns"]:
                if re.search(pat, text, re.IGNORECASE):
                    did_fail = True
                    matched.add(idx)
                    break
            if did_fail:
                break

            # Then pass patterns
            for pat in rule["pass_patterns"]:
                if re.search(pat, text, re.IGNORECASE):
                    did_pass = True
                    matched.add(idx)
                    break
            if did_pass:
                break

        if did_fail:
            results.append((name, "Fail", suggestion))
        elif did_pass:
            results.append((name, "Pass", "-"))
        else:
            results.append((name, "Missing", suggestion))

    # Collect truly unmatched lines
    all_patterns = [pat for r in paloalto_rules for pat in (r["pass_patterns"] + r["fail_patterns"])]
    for idx, raw in enumerate(normalized):
        if idx in matched:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
