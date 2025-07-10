import re

fortinet_rules = [
    {
        "rule": "Admin access should be secured with HTTPS",
        "pass_patterns": [r"set\s+.*admin-https-ssl\s+.*enable", r"https.*admin.*enable"],
        "fail_patterns": [r"set\s+.*admin-https-ssl\s+.*disable", r"admin.*http.*enable"],
        "suggestion": "Enable HTTPS for admin access using: set admin-https-ssl enable"
    },
    {
        "rule": "Enable SCP for secure file transfers",
        "pass_patterns": [r"set\s+.*admin-scp\s+.*enable", r"scp\s+.*enable"],
        "fail_patterns": [r"set\s+.*admin-scp\s+.*disable", r"disable\s+.*scp"],
        "suggestion": "Enable SCP using: set admin-scp enable"
    },
    {
        "rule": "Strong cryptography should be enabled",
        "pass_patterns": [r"set\s+.*strong-crypto\s+.*enable"],
        "fail_patterns": [r"set\s+.*strong-crypto\s+.*disable"],
        "suggestion": "Enable strong crypto using: set strong-crypto enable"
    },
    {
        "rule": "Set admin lockout threshold",
        "pass_patterns": [r"set\s+.*admin-lockout-threshold\s+.*[1-9]+"],
        "fail_patterns": [r"set\s+.*admin-lockout-threshold\s+.*0"],
        "suggestion": "Use: set admin-lockout-threshold 3"
    },
    {
        "rule": "Set admin lockout duration",
        "pass_patterns": [r"set\s+.*admin-lockout-duration\s+.*[1-9]+"],
        "fail_patterns": [r"set\s+.*admin-lockout-duration\s+.*0"],
        "suggestion": "Use: set admin-lockout-duration 60"
    },
    {
        "rule": "Enforce password complexity",
        "pass_patterns": [r"password-profile.*complexity.*enable", r"password-profile.*(lower-case|upper-case|number).*yes"],
        "fail_patterns": [r"password-profile.*complexity.*disable"],
        "suggestion": "Set password profile with complexity enabled: set password-profile complexity enable"
    },
    {
        "rule": "Configure idle timeout for admin console",
        "pass_patterns": [r"set\s+.*admin-console-timeout\s+.*[1-9]+"],
        "fail_patterns": [r"set\s+.*admin-console-timeout\s+.*0"],
        "suggestion": "Use: set admin-console-timeout 10"
    },
    {
        "rule": "Disable Telnet access",
        "pass_patterns": [r"set\s+.*admin-access\s+.*.*ssh.*"],
        "fail_patterns": [r"set\s+.*admin-access\s+.*.*telnet.*"],
        "suggestion": "Avoid using telnet, enable SSH instead for admin access."
    },
    {
        "rule": "Configure trusted hosts for admin access",
        "pass_patterns": [r"set\s+.*trusthost\d+\s+.*\d+\.\d+\.\d+\.\d+"],
        "fail_patterns": [r"set\s+.*trusthost\d+\s+.*0\.0\.0\.0"],
        "suggestion": "Restrict admin access to known IPs using trusthost."
    },
    {
        "rule": "Enable logging to external syslog",
        "pass_patterns": [r"set\s+.*syslog.*enable", r"set\s+.*syslog.*server"],
        "fail_patterns": [r"disable\s+.*syslog", r"no\s+.*syslog"],
        "suggestion": "Enable remote syslog for log collection."
    },
    {
        "rule": "Configure two-factor authentication",
        "pass_patterns": [r"set\s+.*two-factor\s+.*enable", r"set\s+.*auth\s+.*otp"],
        "fail_patterns": [r"set\s+.*two-factor\s+.*disable", r"no\s+.*otp"],
        "suggestion": "Enable 2FA for admin accounts."
    },
    {
        "rule": "Enable Antivirus scanning",
        "pass_patterns": [r"set\s+.*av\s+.*profile.*enable", r"antivirus.*enabled"],
        "fail_patterns": [r"disable\s+.*antivirus", r"no\s+.*av\s+.*scan"],
        "suggestion": "Enable antivirus scanning in UTM profiles."
    },
    {
        "rule": "Enable Web Filtering",
        "pass_patterns": [r"set\s+.*webfilter.*enable"],
        "fail_patterns": [r"disable\s+.*webfilter", r"no\s+.*web\s+.*filter"],
        "suggestion": "Enable web filtering in UTM."
    },
    {
        "rule": "Enable IPS",
        "pass_patterns": [r"set\s+.*ips.*enable", r"ips.*mode.*inline"],
        "fail_patterns": [r"disable\s+.*ips"],
        "suggestion": "Enable IPS to detect and prevent intrusions."
    },
    {
        "rule": "Enable Application Control",
        "pass_patterns": [r"set\s+.*application-control.*enable"],
        "fail_patterns": [r"no\s+.*app\s+.*control"],
        "suggestion": "Enable App Control to regulate application traffic."
    },
    {
        "rule": "Enable Anti-Spam",
        "pass_patterns": [r"set\s+.*spamfilter.*enable"],
        "fail_patterns": [r"disable\s+.*spamfilter"],
        "suggestion": "Enable anti-spam filtering."
    },
    {
        "rule": "Use secure admin ports",
        "pass_patterns": [r"set\s+.*admin-port\s+.*443", r"set\s+.*admin-https-port\s+.*443"],
        "fail_patterns": [r"set\s+.*admin-port\s+.*80"],
        "suggestion": "Use secure port (443) for admin interface."
    },
    {
        "rule": "Enable Geo IP blocking",
        "pass_patterns": [r"set\s+.*geoip.*enable", r"geo-blocking"],
        "fail_patterns": [r"disable\s+.*geoip"],
        "suggestion": "Enable GeoIP filtering to block risky locations."
    },
    {
        "rule": "Enable DNS filtering",
        "pass_patterns": [r"set\s+.*dnsfilter.*enable"],
        "fail_patterns": [r"disable\s+.*dnsfilter"],
        "suggestion": "Enable DNS filtering in firewall policies."
    },
    {
        "rule": "Enable SSL Inspection",
        "pass_patterns": [r"set\s+.*ssl-ssh-profile.*deep-inspection"],
        "fail_patterns": [r"no\s+.*ssl\s+.*inspection", r"disable\s+.*ssl"],
        "suggestion": "Use SSL deep inspection for secure traffic analysis."
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()

    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in fortinet_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw_line in enumerate(normalized):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            text = line.lower()

            # Fail patterns check first
            if not found_fail:
                for pat in rule["fail_patterns"]:
                    if re.search(pat, text):
                        found_fail = True
                        matched_indices.add(idx)
                        break

            # Pass patterns check only if fail not found
            if not found_fail and not found_pass:
                for pat in rule["pass_patterns"]:
                    if re.search(pat, text):
                        found_pass = True
                        matched_indices.add(idx)
                        break

            if found_fail or found_pass:
                break

        if found_fail:
            results.append((name, "Fail", suggestion))
        elif found_pass:
            results.append((name, "Pass", "-"))
        else:
            results.append((name, "Missing", suggestion))

    # Detect unrecognized lines not matched by any rule
    all_patterns = [pat for rule in fortinet_rules for pat in (rule["pass_patterns"] + rule["fail_patterns"])]

    for idx, raw_line in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        # If line doesn't match any known pattern, mark as unrecognized
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
