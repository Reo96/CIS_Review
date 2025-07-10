import re

windows_server_2022_rules = [
    {
        "rule": "Ensure password complexity is enabled",
        "pass_patterns": [r"password\s+.*complexity\s+.*enabled", r"password\s+.*must\s+.*meet\s+.*complexity\s+.*requirements\s*:\s*enabled", r"complex\s+.*password\s+.*policy"],
        "fail_patterns": [r"password\s+.*complexity\s+.*disabled", r"password\s+.*complexity\s+.*off"],
        "suggestion": "Enable password complexity under Local Security Policy > Account Policies."
    },
    {
        "rule": "Ensure minimum password length is 14 or more",
        "pass_patterns": [r"minimum\s+.*password\s+.*length\s*:\s*(1[4-9]|\d{3,})", r"password\s+.*length\s+.*min\s*14"],
        "fail_patterns": [r"minimum\s+.*password\s+.*length\s*:\s*[0-9]|1[0-3]", r"password\s+.*length\s+.*min\s*([0-9]|1[0-3])"],
        "suggestion": "Set minimum password length to 14+ characters via Group Policy."
    },
    {
        "rule": "Ensure account lockout duration is set",
        "pass_patterns": [r"account\s+.*lockout\s+.*duration\s*:\s*\d+", r"lockout\s+.*duration\s+.*>\s*0", r"lockout\s+.*time\s+.*configured"],
        "fail_patterns": [r"account\s+.*lockout\s+.*duration\s*:\s*0", r"lockout\s+.*duration\s*=\s*0"],
        "suggestion": "Set lockout duration to prevent brute-force attempts."
    },
    {
        "rule": "Ensure Windows Defender Antivirus is enabled",
        "pass_patterns": [r"windows\s+.*defender\s+.*antivirus\s+.*enabled", r"antivirus\s+.*status\s+.*active", r"real-time\s+.*protection\s+.*on"],
        "fail_patterns": [r"windows\s+.*defender\s+.*antivirus\s+.*disabled", r"defender\s+.*status\s+.*inactive"],
        "suggestion": "Enable Windows Defender AV from Settings or via PowerShell."
    },
    {
        "rule": "Ensure all firewall profiles are enabled",
        "pass_patterns": [r"domain\s+.*firewall\s+.*on", r"private\s+.*firewall\s+.*enabled", r"public\s+.*firewall\s+.*active"],
        "fail_patterns": [r"firewall\s+.*disabled"],
        "suggestion": "Enable all firewall profiles in Windows Defender Firewall settings."
    },
    {
        "rule": "Ensure audit logon events are enabled",
        "pass_patterns": [r"audit\s+.*logon\s+.*events\s+.*enabled", r"account\s+.*logon\s+.*auditing", r"logon\s+.*activity\s+.*audit"],
        "fail_patterns": [r"audit\s+.*logon\s+.*events\s+.*disabled"],
        "suggestion": "Enable via Group Policy > Audit Policy."
    },
    {
        "rule": "Ensure secure boot is enabled",
        "pass_patterns": [r"secure\s+.*boot\s+.*on", r"uefi\s+.*secure\s+.*boot\s+.*enabled", r"boot\s+.*mode\s+.*secure"],
        "fail_patterns": [r"secure\s+.*boot\s+.*off", r"uefi\s+.*secure\s+.*boot\s+.*disabled"],
        "suggestion": "Enable Secure Boot in BIOS/UEFI."
    },
    {
        "rule": "Ensure SMBv1 is disabled",
        "pass_patterns": [r"smbv1\s+.*disabled", r"smb1\s+.*protocol\s+.*removed", r"smbv1\s+.*feature\s+.*off"],
        "fail_patterns": [r"smbv1\s+.*enabled", r"smb1\s+.*protocol\s+.*on"],
        "suggestion": "Remove SMBv1 from installed features."
    },
    {
        "rule": "Ensure PowerShell logging is enabled",
        "pass_patterns": [r"powershell\s+.*script\s+.*logging\s+.*enabled", r"module\s+.*logging\s+.*on", r"powershell\s+.*transcription\s+.*enabled"],
        "fail_patterns": [r"powershell\s+.*script\s+.*logging\s+.*disabled"],
        "suggestion": "Enable script and module logging via GPO."
    },
    {
        "rule": "Ensure RDP is disabled if not needed",
        "pass_patterns": [r"remote\s+.*desktop\s+.*disabled", r"rdp\s+.*off", r"no\s+.*remote\s+.*access"],
        "fail_patterns": [r"remote\s+.*desktop\s+.*enabled", r"rdp\s+.*on"],
        "suggestion": "Disable RDP in System Properties if not needed."
    },
    {
        "rule": "Ensure AppLocker is enabled",
        "pass_patterns": [r"applocker\s+.*enabled", r"application\s+.*control\s+.*policies", r"software\s+.*restriction\s+.*configured"],
        "fail_patterns": [r"applocker\s+.*disabled"],
        "suggestion": "Enable AppLocker via Group Policy."
    },
    {
        "rule": "Ensure automatic updates are enabled",
        "pass_patterns": [r"automatic\s+.*updates\s+.*on", r"windows\s+.*update\s+.*auto\s+.*download", r"update\s+.*service\s+.*running"],
        "fail_patterns": [r"automatic\s+.*updates\s+.*off", r"windows\s+.*update\s+.*disabled"],
        "suggestion": "Turn on auto-updates via Group Policy or Settings."
    },
    {
        "rule": "Ensure NLA is required for RDP",
        "pass_patterns": [r"network\s+.*level\s+.*authentication\s+.*required", r"nla\s+.*enabled", r"rdp\s+.*authentication\s+.*required"],
        "fail_patterns": [r"network\s+.*level\s+.*authentication\s+.*not\s+.*required", r"nla\s+.*disabled"],
        "suggestion": "Enable NLA for RDP in Remote Desktop settings."
    },
    {
        "rule": "Ensure user rights assignments are restricted",
        "pass_patterns": [r"user\s+.*rights\s+.*assignments\s+.*configured", r"deny\s+.*access\s+.*to\s+.*this\s+.*computer", r"restricted\s+.*logon\s+.*rights"],
        "fail_patterns": [],
        "suggestion": "Harden user rights assignments via GPO."
    },
    {
        "rule": "Ensure Windows Defender SmartScreen is enabled",
        "pass_patterns": [r"smartscreen\s+.*enabled", r"windows\s+.*defender\s+.*smartscreen\s+.*on", r"app\s+.*reputation\s+.*feature\s+.*enabled"],
        "fail_patterns": [r"smartscreen\s+.*disabled", r"windows\s+.*defender\s+.*smartscreen\s+.*off"],
        "suggestion": "Enable SmartScreen in Windows Security."
    },
    {
        "rule": "Ensure anonymous access to shares is disabled",
        "pass_patterns": [r"anonymous\s+.*access\s+.*to\s+.*shares\s+.*disabled", r"restrictanonymous\s+.*set\s+.*to\s+.*1", r"guest\s+.*access\s+.*not\s+.*allowed"],
        "fail_patterns": [],
        "suggestion": "Disable guest/anonymous access to shared folders."
    },
    {
        "rule": "Ensure unnecessary services are disabled",
        "pass_patterns": [r"disable\s+.*telnet\s+.*service", r"disable\s+.*ftp\s+.*server", r"remote\s+.*desktop\s+.*services\s+.*off"],
        "fail_patterns": [],
        "suggestion": "Disable unused services in Services console or via PowerShell."
    },
    {
        "rule": "Ensure security event log is not full",
        "pass_patterns": [r"security\s+.*log\s+.*size\s+.*configured", r"event\s+.*log\s+.*overwrite\s+.*enabled", r"event\s+.*retention\s+.*configured"],
        "fail_patterns": [],
        "suggestion": "Configure log retention and size for security logs."
    },
    {
        "rule": "Ensure remote registry is disabled",
        "pass_patterns": [r"remote\s+.*registry\s+.*service\s+.*disabled", r"regsvc\s+.*disabled", r"disable\s+.*remote\s+.*registry"],
        "fail_patterns": [],
        "suggestion": "Disable remote registry to prevent remote access to the registry."
    },
    {
        "rule": "Ensure automatic logon is disabled",
        "pass_patterns": [r"auto\s+.*logon\s+.*disabled", r"disable\s+.*autologon", r"do\s+.*not\s+.*allow\s+.*automatic\s+.*logon"],
        "fail_patterns": [],
        "suggestion": "Disable auto logon via registry or GPO."
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in windows_server_2022_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            text = line.lower()

            for pat in rule.get("fail_patterns", []):
                if re.search(pat, text, re.IGNORECASE):
                    found_fail = True
                    matched_indices.add(idx)
                    break
            if found_fail:
                break

            for pat in rule.get("pass_patterns", []):
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

    # Identify unrecognized lines
    all_patterns = [pat for rule in windows_server_2022_rules for pat in (rule.get("pass_patterns", []) + rule.get("fail_patterns", []))]

    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
