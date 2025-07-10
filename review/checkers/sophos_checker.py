import re

sophos_rules = [
    {
        "rule": "Disable Telnet management",
        "pass_patterns": [r"telnet\s+.*disable", r"system\s+.*telnet\s+.*disable"],
        "fail_patterns": [r"telnet\s+.*enable", r"system\s+.*telnet\s+.*enable"],
        "suggestion": "Disable Telnet via `system telnet disable`."
    },
    {
        "rule": "Enable SSH management",
        "pass_patterns": [r"ssh\s+.*enable", r"system\s+.*ssh\s+.*enable"],
        "fail_patterns": [r"ssh\s+.*disable", r"system\s+.*ssh\s+.*disable"],
        "suggestion": "Enable SSH via `system ssh enable`."
    },
    {
        "rule": "Disable HTTP admin interface",
        "pass_patterns": [r"http\s+.*admin\s+.*interface\s+.*disable", r"disable\s+.*http\s+.*admin"],
        "fail_patterns": [r"http\s+.*admin\s+.*interface\s+.*enable", r"enable\s+.*http\s+.*admin"],
        "suggestion": "Disable HTTP admin interface."
    },
    {
        "rule": "Enable HTTPS admin interface",
        "pass_patterns": [r"https\s+.*admin\s+.*interface\s+.*enable", r"enable\s+.*https\s+.*admin"],
        "fail_patterns": [r"https\s+.*admin\s+.*interface\s+.*disable", r"disable\s+.*https\s+.*admin"],
        "suggestion": "Enable HTTPS admin interface."
    },
    {
        "rule": "Enforce password policy",
        "pass_patterns": [r"password\s+.*policy\s+.*enable", r"enforce\s+.*password\s+.*policy"],
        "fail_patterns": [r"password\s+.*policy\s+.*disable", r"disable\s+.*password\s+.*policy"],
        "suggestion": "Enable password policy with `password policy enable`."
    },
    {
        "rule": "Set admin idle timeout",
        "pass_patterns": [r"admin\s+.*idle-timeout\s+.*\d+", r"idle-timeout\s+.*\d+"],
        "fail_patterns": [r"admin\s+.*idle-timeout\s+.*0", r"idle-timeout\s+.*0"],
        "suggestion": "Configure admin idle-timeout (e.g. 300 seconds)."
    },
    {
        "rule": "Configure remote syslog",
        "pass_patterns": [r"log\s+.*remote\s+.*\d+\.\d+\.\d+\.\d+", r"system\s+.*log\s+.*remote"],
        "fail_patterns": [],
        "suggestion": "Configure remote syslog server."
    },
    {
        "rule": "Configure NTP server",
        "pass_patterns": [r"system\s+.*time\s+.*ntp", r"ntp\s+.*server\s+.*\d+\.\d+\.\d+\.\d+"],
        "fail_patterns": [],
        "suggestion": "Set NTP server for time synchronization."
    },
    {
        "rule": "Enable event logging",
        "pass_patterns": [r"log\s+.*enable", r"enable\s+.*logging"],
        "fail_patterns": [r"log\s+.*disable", r"disable\s+.*logging"],
        "suggestion": "Enable logging via `log enable`."
    },
    {
        "rule": "Force HTTPS redirection",
        "pass_patterns": [r"force\s+.*https", r"https\s+.*redirect"],
        "fail_patterns": [r"disable\s+.*https\s+.*redirect"],
        "suggestion": "Force HTTPS redirection."
    },
    {
        "rule": "Enable ATP (Advanced Threat Protection)",
        "pass_patterns": [r"enabled\s+.*'?ATP'?", r"enable\s+.*ATP"],
        "fail_patterns": [r"disable\s+.*ATP", r"ATP\s+.*disable"],
        "suggestion": "Enable ATP engine."
    },
    {
        "rule": "Enable intrusion prevention",
        "pass_patterns": [r"enable\s+.*ip\s+.*module", r"IPS\s+.*enable"],
        "fail_patterns": [r"disable\s+.*ip\s+.*module", r"IPS\s+.*disable"],
        "suggestion": "Enable IPS engine."
    },
    {
        "rule": "Enable application control",
        "pass_patterns": [r"enable\s+.*app\s+.*control", r"app-control\s+.*enable"],
        "fail_patterns": [r"disable\s+.*app\s+.*control"],
        "suggestion": "Enable Application Control."
    },
    {
        "rule": "Enable web filtering",
        "pass_patterns": [r"enable\s+.*web\s+.*filter", r"web-filter\s+.*enable"],
        "fail_patterns": [r"disable\s+.*web\s+.*filter"],
        "suggestion": "Enable Web Filtering."
    },
    {
        "rule": "Enable email protection",
        "pass_patterns": [r"enable\s+.*email\s+.*protection", r"email-protection\s+.*enable"],
        "fail_patterns": [r"disable\s+.*email\s+.*protection"],
        "suggestion": "Enable Email Protection."
    },
    {
        "rule": "Enable DLP (Data Loss Prevention)",
        "pass_patterns": [r"enable\s+.*dlp", r"dlp\s+.*enable"],
        "fail_patterns": [r"disable\s+.*dlp"],
        "suggestion": "Enable DLP."
    },
    {
        "rule": "Set device hostname",
        "pass_patterns": [r"device-name\s+.*\s+.*", r"hostname\s+.*\s+.*"],
        "fail_patterns": [],
        "suggestion": "Set device hostname."
    },
    {
        "rule": "Check firmware version",
        "pass_patterns": [r"firmware\s+.*version\s+.*\s+.*", r"version\s+.*\d+\.\d+"],
        "fail_patterns": [],
        "suggestion": "Ensure firmware is updated."
    },
    {
        "rule": "Disable default admin account",
        "pass_patterns": [r"default\s+.*admin\s+.*disable", r"user\s+.*admin\s+.*disable"],
        "fail_patterns": [r"default\s+.*admin\s+.*enable", r"user\s+.*admin\s+.*enable"],
        "suggestion": "Disable default admin account."
    },
    {
        "rule": "Enable two-factor authentication",
        "pass_patterns": [r"two-factor", r"2fa\s+.*enable"],
        "fail_patterns": [r"two-factor\s+.*disable", r"2fa\s+.*disable"],
        "suggestion": "Enable two-factor authentication."
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in sophos_rules:
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
                if re.search(pat, text, re.IGNORECASE):
                    found_fail = True
                    matched_indices.add(idx)
                    break
            if found_fail:
                break

            for pat in rule["pass_patterns"]:
                if re.search(pat, text, re.IGNORECASE):
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

    # Check for unrecognized lines
    all_patterns = [pat for r in sophos_rules for pat in (r["pass_patterns"] + r["fail_patterns"])]

    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
