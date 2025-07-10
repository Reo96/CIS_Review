import re

checkpoint_rules = [
    {
        "rule": "Enable SmartDashboard access via HTTPS only",
        "pass_patterns": [
            r"https\s+.*enabled",
            r"dashboard\s+.*https",
            r"set\s+.*gui\s+.*https"
        ],
        "fail_patterns": [
            r"http\s+.*enabled",
            r"dashboard\s+.*http",
            r"set\s+.*gui\s+.*http"
        ],
        "suggestion": "Restrict SmartDashboard to HTTPS only."
    },
    {
        "rule": "Configure SSH access",
        "pass_patterns": [
            r"ssh\s+.*enabled",
            r"set\s+.*ssh\s+.*access",
            r"ssh\s+.*allow"
        ],
        "fail_patterns": [
            r"no\s+.*ssh",
            r"disable\s+.*ssh"
        ],
        "suggestion": "Enable SSH for secure admin access."
    },
    {
        "rule": "Disable unused VPN communities",
        "pass_patterns": [
            r"vpn\s+.*community\s+.*disabled",
            r"no\s+.*vpn",
            r"disable\s+.*vpn"
        ],
        "fail_patterns": [
            r"vpn\s+.*community\s+.*enabled",
            r"enable\s+.*vpn"
        ],
        "suggestion": "Remove unused VPN communities."
    },
    {
        "rule": "Restrict GUI clients by IP",
        "pass_patterns": [
            r"gui-clients\s+.*\d+\.\d+\.\d+\.\d+",
            r"trusted\s+.*clients",
            r"allowed\s+.*gui\s+.*ip"
        ],
        "fail_patterns": [
            r"gui-clients\s+.*any",
            r"gui\s+.*clients\s+.*0\.0\.0\.0"
        ],
        "suggestion": "Restrict GUI access to known IPs only."
    },
    {
        "rule": "Disable dangerous services on interfaces",
        "pass_patterns": [
            r"disable\s+.*services",
            r"no\s+.*icmp",
            r"disable\s+.*snmp"
        ],
        "fail_patterns": [
            r"enable\s+.*icmp",
            r"enable\s+.*snmp"
        ],
        "suggestion": "Turn off unused services on interfaces."
    },
    {
        "rule": "Enable Threat Prevention",
        "pass_patterns": [
            r"threat\s+.*prevention",
            r"threat\s+.*profile",
            r"enable\s+.*ips"
        ],
        "fail_patterns": [
            r"disable\s+.*ips",
            r"no\s+.*threat\s+.*prevention"
        ],
        "suggestion": "Enable IPS, AV, AB, Threat Emulation."
    },
    {
        "rule": "Enable Anti-Bot protection",
        "pass_patterns": [
            r"anti-bot",
            r"enable\s+.*bot\s+.*defense",
            r"bot\s+.*profile"
        ],
        "fail_patterns": [
            r"no\s+.*anti-bot",
            r"disable\s+.*bot\s+.*defense"
        ],
        "suggestion": "Enable Anti-Bot to detect botnet traffic."
    },
    {
        "rule": "Configure strong password policy",
        "pass_patterns": [
            r"password\s+.*complexity",
            r"min\s+.*password\s+.*length\s+.*\d+",
            r"secure\s+.*password"
        ],
        "fail_patterns": [
            r"min\s+.*password\s+.*length\s+.*[1-6]",
            r"password\s+.*policy\s+.*disabled"
        ],
        "suggestion": "Set password complexity and length rules."
    },
    {
        "rule": "Enable Logging to external server",
        "pass_patterns": [
            r"set\s+.*log\s+.*server",
            r"log\s+.*external",
            r"forward\s+.*logs"
        ],
        "fail_patterns": [
            r"log\s+.*local\s+.*only",
            r"disable\s+.*external\s+.*logging"
        ],
        "suggestion": "Enable log export to external syslog."
    },
    {
        "rule": "Enable regular GAIA software updates",
        "pass_patterns": [
            r"auto-update",
            r"update\s+.*gaia",
            r"set\s+.*auto\s+.*update"
        ],
        "fail_patterns": [
            r"no\s+.*auto-update",
            r"disable\s+.*auto\s+.*update"
        ],
        "suggestion": "Enable auto-updates for GAIA software."
    },
    {
        "rule": "Enable session timeouts",
        "pass_patterns": [
            r"timeout\s+.*session",
            r"set\s+.*session\s+.*timeout",
            r"idle\s+.*timeout"
        ],
        "fail_patterns": [
            r"idle\s+.*timeout\s+.*0",
            r"no\s+.*session\s+.*timeout"
        ],
        "suggestion": "Set session timeout limits."
    },
    {
        "rule": "Enable admin lockout policy",
        "pass_patterns": [
            r"admin\s+.*lockout",
            r"login\s+.*attempts\s+.*limit",
            r"set\s+.*admin\s+.*retries"
        ],
        "fail_patterns": [
            r"unlimited\s+.*admin\s+.*retries",
            r"admin\s+.*lockout\s+.*disabled"
        ],
        "suggestion": "Limit failed admin logins and lock account."
    },
    {
        "rule": "Set warning banners",
        "pass_patterns": [
            r"banner\s+.*warning",
            r"set\s+.*login\s+.*banner"
        ],
        "fail_patterns": [
            r"no\s+.*banner",
            r"banner\s+.*off"
        ],
        "suggestion": "Use a legal banner for login."
    },
    {
        "rule": "Disable unused admin accounts",
        "pass_patterns": [
            r"delete\s+.*user",
            r"remove\s+.*admin",
            r"disable\s+.*account"
        ],
        "fail_patterns": [
            r"default\s+.*admin\s+.*active",
            r"unused\s+.*account\s+.*enabled"
        ],
        "suggestion": "Disable or remove unused accounts."
    },
    {
        "rule": "Enable 2FA for management login",
        "pass_patterns": [
            r"two-factor\s+.*auth",
            r"2fa\s+.*login",
            r"otp\s+.*auth"
        ],
        "fail_patterns": [
            r"no\s+.*2fa",
            r"disable\s+.*otp"
        ],
        "suggestion": "Use 2FA for privileged users."
    },
    {
        "rule": "Restrict user shell access",
        "pass_patterns": [
            r"set\s+.*user\s+.*shell",
            r"shell\s+.*rbash",
            r"restricted\s+.*shell"
        ],
        "fail_patterns": [
            r"shell\s+.*/bin/bash",
            r"user\s+.*shell\s+.*full"
        ],
        "suggestion": "Use restricted shells for users."
    },
    {
        "rule": "Enable Anti-Virus scanning",
        "pass_patterns": [
            r"anti-virus",
            r"enable\s+.*av",
            r"scan\s+.*virus"
        ],
        "fail_patterns": [
            r"no\s+.*anti-virus",
            r"disable\s+.*av"
        ],
        "suggestion": "Enable AV scanning on gateways."
    },
    {
        "rule": "Enable Geo IP Filtering",
        "pass_patterns": [
            r"geo-ip\s+.*enable",
            r"country\s+.*filter",
            r"location\s+.*based\s+.*block"
        ],
        "fail_patterns": [
            r"allow\s+.*all\s+.*countries",
            r"geo-ip\s+.*disabled"
        ],
        "suggestion": "Block traffic from high-risk regions."
    },
    {
        "rule": "Enable DNS Trap protection",
        "pass_patterns": [
            r"dns\s+.*trap",
            r"set\s+.*dns\s+.*protect"
        ],
        "fail_patterns": [
            r"no\s+.*dns\s+.*trap",
            r"dns\s+.*trap\s+.*disabled"
        ],
        "suggestion": "Use DNS trap to detect tunneling."
    },
    {
        "rule": "Enable access roles",
        "pass_patterns": [
            r"access-role",
            r"user-role",
            r"rbac\s+.*role"
        ],
        "fail_patterns": [
            r"disable\s+.*role",
            r"no\s+.*rbac"
        ],
        "suggestion": "Use roles to control access rights."
    },
    {
    "rule": "Restrict GUI clients access",
    "pass_patterns": [
        r"gui-clients\s+.*\d+\.\d+\.\d+\.\d+",  # IP addresses allowed
        r"trusted\s+.*clients",
        r"allowed\s+.*gui\s+.*ip"
    ],
    "fail_patterns": [
        r"gui-clients\s+.*any",      # GUI clients set to any (bad)
        r"gui\s+.*clients\s+.*any",      # GUI clients set to any (bad)
        r"gui\s+.*clients\s+.*0\.0\.0\.0"
    ],
    "suggestion": "Restrict GUI access to specific IPs, not 'any' or '0.0.0.0'."
    },
    {
        "rule": "Enable dangerous services on interfaces",
        "pass_patterns": [
            r"disable\s+.*services",
            r"no\s+.*icmp",
            r"disable\s+.*snmp"
        ],
        "fail_patterns": [
            r"enable\s+.*services",
            r"enable\s+.*icmp",
            r"enable\s+.*snmp"
        ],
        "suggestion": "Disable dangerous/unnecessary services on interfaces."
    },
    {
        "rule": "Configure strong password minimum length",
        "pass_patterns": [
            r"min\s+.*password\s+.*length\s+.*[7-9]+",  # length 7 or more good
            r"password\s+.*complexity"
        ],
        "fail_patterns": [
            r"min\s+.*password\s+.*length\s+.*[1-6]",  # less than 7 is weak
            r"password\s+.*policy\s+.*disabled"
        ],
        "suggestion": "Set minimum password length to 7 or more."
    },
    {
        "rule": "Set admin retry lockout limits",
        "pass_patterns": [
            r"admin\s+.*lockout",
            r"login\s+.*attempts\s+.*limit",
            r"set\s+.*admin\s+.*retries\s+.*\d+"
        ],
        "fail_patterns": [
            r"admin\s+.*retries\s+.*unlimited",
            r"unlimited\s+.*admin\s+.*retries",
            r"admin\s+.*lockout\s+.*disabled"
        ],
        "suggestion": "Limit admin login retries to prevent brute force."
    },
    {
        "rule": "Set login banner",
        "pass_patterns": [
            r"banner\s+.*warning",
            r"set\s+.*login\s+.*banner"
        ],
        "fail_patterns": [
            r"no\s+.*banner",
            r"banner\s+.*disabled",
            r"banner\s+.*off"
        ],
        "suggestion": "Set a login warning banner for legal notice."
    },
    {
        "rule": "Enable deep inspection of all traffic",
        "pass_patterns": [
            r"enable\s+.*deep-inspect-all-traffic",
            r"deep-inspection\s+.*enabled"
        ],
        "fail_patterns": [
            r"disable\s+.*deep-inspect-all-traffic",
            r"deep-inspection\s+.*disabled"
        ],
        "suggestion": "Enable deep inspection to enhance traffic analysis."
    },
    {
        "rule": "Unknown or custom commands",
        "pass_patterns": [
            r"custom\s+.*command\s+.*xyz\s+.*enable"
        ],
        "fail_patterns": [],
        "suggestion": "Check custom commands to ensure compliance."
    }

]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in checkpoint_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('!') or line.startswith('#'):
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

    # Detect Unknown lines
    for idx, raw in enumerate(normalized):
        line = raw.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
        if idx not in matched_indices:
            results.append((line, "Unknown", "No matching benchmark rule for this configuration."))

    return results
