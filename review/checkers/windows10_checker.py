import re

windows10_rules = [
    {
        "rule": "Password must meet complexity requirements",
        "pass_patterns": [r"password\s+.*complexity\s+.*enabled", r"complexity\s+.*requirements\s+.*enabled"],
        "fail_patterns": [r"password\s+.*complexity\s+.*disabled", r"complexity\s+.*requirements\s+.*disabled"],
        "suggestion": "Enable password complexity via Group Policy or secpol.msc"
    },
    {
        "rule": "Minimum password length of 14 characters",
        "pass_patterns": [r"minimum\s+.*password\s+.*length\s+.*1[4-9]", r"password\s+.*length\s+.*>=\s*14"],
        "fail_patterns": [r"minimum\s+.*password\s+.*length\s+.*(?!1[4-9]|\d{3,})", r"password\s+.*length\s+.*<\s*14"],
        "suggestion": "Set minimum password length to 14 in Group Policy"
    },
    {
        "rule": "Account lockout threshold set to 5 or less",
        "pass_patterns": [r"account\s+.*lockout\s+.*threshold\s+.*[0-5]", r"lockout\s+.*threshold\s+.*5"],
        "fail_patterns": [r"account\s+.*lockout\s+.*threshold\s+.*[6-9]", r"lockout\s+.*threshold\s+.*>\s*5"],
        "suggestion": "Set account lockout threshold to 5 or less"
    },
    {
        "rule": "Windows Defender Antivirus real-time protection enabled",
        "pass_patterns": [r"real-time\s+.*protection\s+.*enabled", r"windows\s+.*defender\s+.*real-time\s+.*on"],
        "fail_patterns": [r"real-time\s+.*protection\s+.*disabled", r"windows\s+.*defender\s+.*real-time\s+.*off"],
        "suggestion": "Enable Windows Defender real-time protection"
    },
    {
        "rule": "Windows Firewall: Domain Profile - Firewall state is on",
        "pass_patterns": [r"domain\s+.*firewall\s+.*state\s+.*on", r"firewall\s+.*domain\s+.*enabled"],
        "fail_patterns": [r"domain\s+.*firewall\s+.*state\s+.*off", r"firewall\s+.*domain\s+.*disabled"],
        "suggestion": "Ensure domain firewall is enabled"
    },
    {
        "rule": "Audit Logon Events enabled",
        "pass_patterns": [r"audit\s+.*logon\s+.*events\s+.*enabled", r"audit\s+.*logon\s+.*success"],
        "fail_patterns": [r"audit\s+.*logon\s+.*events\s+.*disabled"],
        "suggestion": "Enable Audit Logon Events in audit policy"
    },
    {
        "rule": "Guest account is disabled",
        "pass_patterns": [r"guest\s+.*account\s+.*disabled", r"account\s+.*guest\s+.*status\s+.*disabled"],
        "fail_patterns": [r"guest\s+.*account\s+.*enabled", r"account\s+.*guest\s+.*status\s+.*enabled"],
        "suggestion": "Disable Guest account through Local Users and Groups"
    },
    {
        "rule": "Turn off SMBv1 protocol",
        "pass_patterns": [r"smbv1\s+.*disabled", r"remove\s+.*feature\s+.*smb1"],
        "fail_patterns": [r"smbv1\s+.*enabled", r"feature\s+.*smb1\s+.*installed"],
        "suggestion": "Disable SMBv1 via Windows Features or PowerShell"
    },
    {
        "rule": "Disable Anonymous SID/Name Translation",
        "pass_patterns": [r"anonymous\s+.*sid\s+.*translation\s+.*disabled", r"lsass\s+.*anonymous\s+.*sid\s+.*off"],
        "fail_patterns": [r"anonymous\s+.*sid\s+.*translation\s+.*enabled"],
        "suggestion": "Disable via Local Security Policy"
    },
    {
        "rule": "Enable 'Do not display last user name'",
        "pass_patterns": [r"do\s+.*not\s+.*display\s+.*last\s+.*user", r"hide\s+.*last\s+.*user\s+.*logon"],
        "fail_patterns": [r"display\s+.*last\s+.*user\s+.*enabled"],
        "suggestion": "Set this in Local Security Policy > Interactive Logon"
    },
    {
        "rule": "UAC: Admin Approval Mode for the Built-in Administrator account",
        "pass_patterns": [r"admin\s+.*approval\s+.*mode\s+.*enabled", r"uac\s+.*builtin\s+.*admin\s+.*on"],
        "fail_patterns": [r"admin\s+.*approval\s+.*mode\s+.*disabled"],
        "suggestion": "Enable UAC Admin Approval Mode"
    },
    {
        "rule": "Audit Policy: Audit Account Management Success and Failure",
        "pass_patterns": [r"audit\s+.*account\s+.*management\s+.*success", r"audit\s+.*account\s+.*management\s+.*failure"],
        "fail_patterns": [r"audit\s+.*account\s+.*management\s+.*disabled"],
        "suggestion": "Enable success and failure auditing for Account Management"
    },
    {
        "rule": "Windows Defender Antivirus turned on",
        "pass_patterns": [r"windows\s+.*defender\s+.*enabled", r"defender\s+.*antivirus\s+.*on"],
        "fail_patterns": [r"windows\s+.*defender\s+.*disabled", r"defender\s+.*antivirus\s+.*off"],
        "suggestion": "Enable Windows Defender Antivirus"
    },
    {
        "rule": "BitLocker enabled for OS drive",
        "pass_patterns": [r"bitlocker\s+.*enabled", r"os\s+.*drive\s+.*bitlocker\s+.*on"],
        "fail_patterns": [r"bitlocker\s+.*disabled", r"bitlocker\s+.*off"],
        "suggestion": "Enable BitLocker drive encryption"
    },
    {
        "rule": "Automatic Updates enabled",
        "pass_patterns": [r"automatic\s+.*updates\s+.*enabled", r"windows\s+.*update\s+.*auto\s+.*on"],
        "fail_patterns": [r"automatic\s+.*updates\s+.*disabled", r"windows\s+.*update\s+.*off"],
        "suggestion": "Turn on automatic updates"
    },
    {
        "rule": "Remote Desktop disabled if not needed",
        "pass_patterns": [r"remote\s+.*desktop\s+.*disabled", r"rdp\s+.*service\s+.*off"],
        "fail_patterns": [r"remote\s+.*desktop\s+.*enabled", r"rdp\s+.*service\s+.*on"],
        "suggestion": "Disable Remote Desktop if not required"
    },
    {
        "rule": "Disable LM hash storage",
        "pass_patterns": [r"lm\s+.*hash\s+.*disabled", r"store\s+.*lm\s+.*hash\s+.*off"],
        "fail_patterns": [r"lm\s+.*hash\s+.*enabled"],
        "suggestion": "Prevent storage of LM hashes"
    },
    {
        "rule": "Account lockout duration set to 15 minutes or more",
        "pass_patterns": [r"lockout\s+.*duration\s+.*1[5-9]", r"account\s+.*lock\s+.*15\s+.*minutes"],
        "fail_patterns": [r"lockout\s+.*duration\s+.*<\s*15", r"account\s+.*lock\s+.*duration\s+.*[0-9]"],
        "suggestion": "Set lockout duration to minimum 15 minutes"
    },
    {
        "rule": "Set Maximum password age to 60 days or less",
        "pass_patterns": [r"password\s+.*age\s+.*[0-5]?[0-9]", r"max\s+.*password\s+.*age\s+.*<=\s*60"],
        "fail_patterns": [r"password\s+.*age\s+.*>?\s*6[1-9]", r"max\s+.*password\s+.*age\s+.*>?\s*60"],
        "suggestion": "Configure password expiration policy"
    },
    {
        "rule": "Disable Ctrl+Alt+Del requirement for logon",
        "pass_patterns": [r"ctrl\+alt\+del\s+.*not\s+.*required", r"logon\s+.*without\s+.*ctrl\+alt\+del"],
        "fail_patterns": [r"ctrl\+alt\+del\s+.*required", r"secure\s+.*logon\s+.*enabled"],
        "suggestion": "Allow logon without Ctrl+Alt+Del"
    }
]


def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in windows10_rules:
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

    all_patterns = [pat for r in windows10_rules for pat in (r["pass_patterns"] + r["fail_patterns"])]

    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
