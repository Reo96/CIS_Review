import re

suse_rules = [
    {
      "rule": "Ensure AppArmor is enabled",
      "pass_patterns": [r"^apparmor=.*(enabled|1)\b"],
      "fail_patterns": [r"apparmor=.*(disabled|0)\b"],
      "suggestion": "Enable AppArmor in `/etc/sysconfig/apparmor`"
    },
    {
      "rule": "Ensure password hashing algorithm is SHA‑512",
      "pass_patterns": [r"^ENCRYPT_METHOD=SHA512"],
      "fail_patterns": [r"ENCRYPT_METHOD=(?:MD5|SHA1)"],
      "suggestion": "Set `ENCRYPT_METHOD=SHA512` in `/etc/login.defs`"
    },
    {
      "rule": "Ensure minimum password length is 14 or more",
      "pass_patterns": [r"^PASS_MIN_LEN\s+1[4-9]\b"],
      "fail_patterns": [r"^PASS_MIN_LEN\s+[0-1]?\d\b"],
      "suggestion": "Set `PASS_MIN_LEN 14` in `/etc/login.defs`"
    },
    {
      "rule": "Ensure password complexity is enforced",
      "pass_patterns": [r"pam_pwquality\.so.*(retry=|minlen=)"],
      "fail_patterns": [r"retry=0", r"minlen=[1-7]\b"],
      "suggestion": "Configure `pam_pwquality.so retry=3 minlen=14` in PAM"
    },
    {
      "rule": "Ensure account lockout for failed logins",
      "pass_patterns": [r"pam_faillock\.so.*deny=\d+"],
      "fail_patterns": [r"deny=0"],
      "suggestion": "Use `pam_faillock.so deny=5` in PAM configs"
    },
    {
      "rule": "Ensure SSH Protocol 2 only",
      "pass_patterns": [r"^Protocol\s+2\b"],
      "fail_patterns": [r"^Protocol\s+1\b"],
      "suggestion": "Set `Protocol 2` in `/etc/ssh/sshd_config`"
    },
    {
      "rule": "Ensure root SSH login is disabled",
      "pass_patterns": [r"^PermitRootLogin\s+no\b"],
      "fail_patterns": [r"^PermitRootLogin\s+yes\b"],
      "suggestion": "Set `PermitRootLogin no` in `/etc/ssh/sshd_config`"
    },
    {
      "rule": "Ensure SSH X11 forwarding is disabled",
      "pass_patterns": [r"^X11Forwarding\s+no\b"],
      "fail_patterns": [r"^X11Forwarding\s+yes\b"],
      "suggestion": "Set `X11Forwarding no` in `/etc/ssh/sshd_config`"
    },
    {
      "rule": "Ensure firewalld is active",
      "pass_patterns": [r"firewalld\s+.*(running|enabled)"],
      "fail_patterns": [r"firewalld\s+.*(dead|disabled)"],
      "suggestion": "Enable: `systemctl enable --now firewalld`"
    },
    {
      "rule": "Ensure NTP is configured",
      "pass_patterns": [r"^server\s+\d+\.\d+\.\d+\.\d+"],
      "fail_patterns": [r"^server\s+127\.0\.0\.1"],
      "suggestion": "Configure `/etc/ntp.conf`"
    },
    {
      "rule": "Ensure AIDE is installed",
      "pass_patterns": [r"\baide\b"],
      "fail_patterns": [r"^#.*aide\b"],
      "suggestion": "Install and init AIDE: `zypper install aide && aide --init`"
    },
    {
      "rule": "Ensure auditd is enabled",
      "pass_patterns": [r"auditd\s+.*(running|enabled)"],
      "fail_patterns": [r"auditd\s+.*(dead|disabled)"],
      "suggestion": "Enable: `systemctl enable --now auditd`"
    },
    {
      "rule": "Ensure core dumps are restricted",
      "pass_patterns": [r"^\*\s+hard\s+core\s+0\b"],
      "fail_patterns": [r"hard\s+core\s+unlimited\b"],
      "suggestion": "Add `* hard core 0` to `/etc/security/limits.conf`"
    },
    {
      "rule": "Ensure permissions on /etc/passwd are 644",
      "pass_patterns": [r"^-rw-r--r--.* /etc/passwd"],
      "fail_patterns": [r"^-rw-------.* /etc/passwd"],
      "suggestion": "Run `chmod 644 /etc/passwd`"
    },
    {
      "rule": "Ensure permissions on /etc/shadow are 600",
      "pass_patterns": [r"^-rw-------.* /etc/shadow"],
      "fail_patterns": [r"^-rw-r--r--.* /etc/shadow"],
      "suggestion": "Run `chmod 600 /etc/shadow`"
    },
    {
      "rule": "Ensure USB storage is disabled",
      "pass_patterns": [r"install usb-storage /bin/true"],
      "fail_patterns": [r"\busb-storage\b"],
      "suggestion": "Add `install usb-storage /bin/true` to a modprobe conf"
    },
    {
      "rule": "Ensure IPv6 is disabled if not used",
      "pass_patterns": [r"^net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1"],
      "fail_patterns": [r"^net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*0"],
      "suggestion": "Add `net.ipv6.conf.all.disable_ipv6=1` to `/etc/sysctl.conf`"
    },
    {
      "rule": "Ensure AppArmor is in enforce mode",
      "pass_patterns": [r"aa-enforce"],
      "fail_patterns": [r"aa-complain"],
      "suggestion": "Run `aa-enforce` on all profiles"
    },
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in suse_rules:
        name       = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            # fail first
            for pat in rule["fail_patterns"]:
                if re.search(pat, line, re.IGNORECASE):
                    found_fail = True
                    matched_indices.add(idx)
                    break
            if found_fail:
                break
            # then pass
            for pat in rule["pass_patterns"]:
                if re.search(pat, line, re.IGNORECASE):
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

    # Unknown lines
    all_patterns = [p for r in suse_rules for p in (r["pass_patterns"] + r["fail_patterns"])]
    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if not any(re.search(pat, line, re.IGNORECASE) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
