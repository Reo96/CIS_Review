import re

fortinet_rules = [
    {
        "rule": "Admin access secured with HTTPS",
        "pass_patterns": [
            r"\bset\s+.*admin-https-ssl\s+.*enable\b",
            r"\bhttps\b.*\badmin\b.*\benable\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-https-ssl\s+.*disable\b",
            r"\badmin\b.*\bhttp\b.*\benable\b"
        ],
        "suggestion": "Enable HTTPS for admin access: set admin-https-ssl enable"
    },
    {
        "rule": "SCP enabled for secure file transfers",
        "pass_patterns": [
            r"\bset\s+.*admin-scp\s+.*enable\b",
            r"\bscp\s+.*enable\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-scp\s+.*disable\b",
            r"\bdisable\s+.*scp\b"
        ],
        "suggestion": "Enable SCP: set admin-scp enable"
    },
    {
        "rule": "Strong cryptography enabled",
        "pass_patterns": [
            r"\bset\s+.*strong-crypto\s+.*enable\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*strong-crypto\s+.*disable\b"
        ],
        "suggestion": "Enable strong-crypto: set strong-crypto enable"
    },
    {
        "rule": "Admin lockout threshold set",
        "pass_patterns": [
            r"\bset\s+.*admin-lockout-threshold\s+.*([1-9]\d*)\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-lockout-threshold\s+.*0\b"
        ],
        "suggestion": "Set threshold: set admin-lockout-threshold 3"
    },
    {
        "rule": "Admin lockout duration set",
        "pass_patterns": [
            r"\bset\s+.*admin-lockout-duration\s+.*([1-9]\d*)\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-lockout-duration\s+.*0\b"
        ],
        "suggestion": "Set duration: set admin-lockout-duration 60"
    },
    {
        "rule": "Password complexity enforced",
        "pass_patterns": [
            r"\bpassword-profile\b.*\bcomplexity\b.*\benable\b",
            r"\b(password-profile\b.*(lower-case|upper-case|number)\b.*\byes\b)"
        ],
        "fail_patterns": [
            r"\bpassword-profile\b.*\bcomplexity\b.*\bdisable\b"
        ],
        "suggestion": "Enable complexity: set password-profile complexity enable"
    },
    {
        "rule": "Idle timeout configured",
        "pass_patterns": [
            r"\bset\s+.*admin-console-timeout\s+.*([1-9]\d*)\b",
            r"\bconsole\s+.*timeout\s+.*([1-9]\d*)\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-console-timeout\s+.*0\b"
        ],
        "suggestion": "Set idle timeout: set admin-console-timeout 10"
    },
    {
        "rule": "Telnet disabled for admin",
        "pass_patterns": [
            r"\bset\s+.*admin-access\b.*\bssh\b",
            r"\bno\s+.*telnet\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-access\b.*\btelnet\b"
        ],
        "suggestion": "Disable telnet, allow SSH: set admin-access <vdom> ssh"
    },
    {
        "rule": "Trusted hosts restricted",
        "pass_patterns": [
            r"\bset\s+.*trusthost\d+\s+.*\d+\.\d+\.\d+\.\d+\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*trusthost\d+\s+.*0\.0\.0\.0\b"
        ],
        "suggestion": "Restrict hosts: set trusthost1 192.168.1.100"
    },
    {
        "rule": "External syslog enabled",
        "pass_patterns": [
            r"\bset\s+.*syslog.*\benable\b",
            r"\bset\s+.*syslog.*\bserver\b"
        ],
        "fail_patterns": [
            r"\bno\s+.*syslog\b",
            r"\bdisable\s+.*syslog\b"
        ],
        "suggestion": "Enable remote syslog: set syslog server <IP>"
    },
    {
        "rule": "Two-factor authentication enabled",
        "pass_patterns": [
            r"\bset\s+.*two-factor\b.*\benable\b",
            r"\bset\s+.*auth\s+.*otp\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*two-factor\b.*\bdisable\b",
            r"\bno\s+.*otp\b"
        ],
        "suggestion": "Enable 2FA: set two-factor enable"
    },
    {
        "rule": "Antivirus scanning enabled",
        "pass_patterns": [
            r"\bset\s+.*av-profile\b.*\benable\b",
            r"\bantivirus.*\benabled\b"
        ],
        "fail_patterns": [
            r"\bdisable\s+.*antivirus\b",
            r"\bno\s+.*av\b"
        ],
        "suggestion": "Enable AV: set av-profile <name> inspection-mode proxy-based"
    },
    {
        "rule": "Web Filtering enabled",
        "pass_patterns": [
            r"\bset\s+.*webfilter-profile\b.*\benable\b"
        ],
        "fail_patterns": [
            r"\bdisable\s+.*webfilter\b",
            r"\bno\s+.*webfilter\b"
        ],
        "suggestion": "Enable webfilter: set webfilter-profile <name> inspection-mode default"
    },
    {
        "rule": "IPS enabled",
        "pass_patterns": [
            r"\bset\s+.*ips-signature\b.*\benable\b",
            r"\bips.*\binline\b"
        ],
        "fail_patterns": [
            r"\bdisable\s+.*ips\b"
        ],
        "suggestion": "Enable IPS: set ips sensor <name> ips enable"
    },
    {
        "rule": "Application Control enabled",
        "pass_patterns": [
            r"\bset\s+.*application-list\b.*\benable\b"
        ],
        "fail_patterns": [
            r"\bno\s+.*application-list\b"
        ],
        "suggestion": "Enable App Control: set application-list <name> application default-apps"
    },
    {
        "rule": "Anti‑Spam enabled",
        "pass_patterns": [
            r"\bset\s+.*spamfilter\b.*\benable\b"
        ],
        "fail_patterns": [
            r"\bdisable\s+.*spamfilter\b"
        ],
        "suggestion": "Enable spamfilter: set spamfilter profile <name> protocols smtp"
    },
    {
        "rule": "Admin port set to 443",
        "pass_patterns": [
            r"\bset\s+.*admin-port\s+.*443\b",
            r"\bset\s+.*admin-https-port\s+.*443\b"
        ],
        "fail_patterns": [
            r"\bset\s+.*admin-port\s+.*80\b"
        ],
        "suggestion": "Use port 443: set admin-port 443"
    },
    {
        "rule": "GeoIP blocking enabled",
        "pass_patterns": [
            r"\bset\s+.*geoip-filter\b.*\benable\b",
            r"\bgeo-blocking\b"
        ],
        "fail_patterns": [
            r"\bdisable\s+.*geoip\b"
        ],
        "suggestion": "Enable GeoIP filter: set geoip-filter <name> entries"
    },
    {
        "rule": "DNS filtering enabled",
        "pass_patterns": [
            r"\bset\s+.*dnsfilter-profile\b.*\benable\b"
        ],
        "fail_patterns": [
            r"\bdisable\s+.*dnsfilter\b"
        ],
        "suggestion": "Enable DNS filter: set dnsfilter-profile <name> domain-filter"
    },
    {
        "rule": "SSL inspection (deep) enabled",
        "pass_patterns": [
            r"\bset\s+.*ssl-ssh-profile\b.*\bdeep-inspection\b"
        ],
        "fail_patterns": [
            r"\bno\s+.*ssl-inspection\b",
            r"\bdisable\s+.*ssl\b"
        ],
        "suggestion": "Enable SSL deep inspection: set ssl-ssh-profile <name> deep-inspection enable"
    },
]

def check_rules(config_lines):
    results = []
    matched = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    # Evaluate each Fortinet rule
    for rule in fortinet_rules:
        name      = rule["rule"]
        suggestion= rule["suggestion"]
        did_pass  = False
        did_fail  = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            text = line.lower()

            # 1) Fail first
            for pat in rule["fail_patterns"]:
                if re.search(pat, text):
                    did_fail = True
                    matched.add(idx)
                    break
            if did_fail:
                break

            # 2) Then pass
            for pat in rule["pass_patterns"]:
                if re.search(pat, text):
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

    # 3) Collect any truly unmatched lines
    all_patterns = [pat for r in fortinet_rules for pat in (r["pass_patterns"] + r["fail_patterns"])]
    for idx, raw in enumerate(normalized):
        if idx in matched:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
