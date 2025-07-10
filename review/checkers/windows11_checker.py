import re

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    windows11_rules = [
        {
            "rule": "Ensure password complexity is enabled",
            "pass_patterns": [
                r"password\s+.*must\s+.*meet\s+.*complexity\s+.*requirements\s*:\s*enabled",
                r"complexity\s+.*requirements\s+.*enabled",
                r"password\s+.*complex\s+.*enabled"
            ],
            "fail_patterns": [
                r"password\s+.*must\s+.*meet\s+.*complexity\s+.*requirements\s*:\s*disabled",
                r"complexity\s+.*requirements\s+.*disabled",
                r"password\s+.*complex\s+.*disabled"
            ],
            "suggestion": "Enable password complexity in Local Security Policy under Account Policies."
        },
        {
            "rule": "Ensure firewall is enabled",
            "pass_patterns": [
                r"firewall\s+.*state\s*:\s*on",
                r"windows\s+.*defender\s+.*firewall\s+.*enabled",
                r"firewall\s+.*enabled"
            ],
            "fail_patterns": [
                r"firewall\s+.*state\s*:\s*off",
                r"windows\s+.*defender\s+.*firewall\s+.*disabled"
            ],
            "suggestion": "Enable Windows Firewall through Control Panel or Group Policy."
        },
        {
            "rule": "Ensure BitLocker is enabled",
            "pass_patterns": [
                r"bitlocker\s+.*status\s*:\s*on",
                r"bitlocker\s+.*enabled",
                r"bitlocker\s+.*protection\s+.*on"
            ],
            "fail_patterns": [
                r"bitlocker\s+.*status\s*:\s*off",
                r"bitlocker\s+.*disabled"
            ],
            "suggestion": "Enable BitLocker drive encryption through Control Panel > BitLocker."
        },
        {
            "rule": "Ensure UAC is enabled",
            "pass_patterns": [
                r"user\s+.*account\s+.*control\s+.*enabled",
                r"uac\s+.*enabled",
                r"enablelua\s*=\s*1"
            ],
            "fail_patterns": [
                r"user\s+.*account\s+.*control\s+.*disabled",
                r"uac\s+.*disabled",
                r"enablelua\s*=\s*0"
            ],
            "suggestion": "Enable UAC via Registry or Group Policy."
        },
        {
            "rule": "Ensure guest account is disabled",
            "pass_patterns": [
                r"guest\s+.*account\s+.*status\s*:\s*disabled",
                r"account\s+.*guest\s+.*disabled",
                r"guest\s+.*user\s+.*disabled"
            ],
            "fail_patterns": [
                r"guest\s+.*account\s+.*status\s*:\s*enabled",
                r"account\s+.*guest\s+.*enabled"
            ],
            "suggestion": "Disable guest account in Local Users and Groups."
        },
        {
            "rule": "Ensure SMBv1 is disabled",
            "pass_patterns": [
                r"smb1\s+.*protocol\s+.*disabled",
                r"smbv1\s+.*disabled",
                r"remove-windowsfeature\s+.*fs-smb1"
            ],
            "fail_patterns": [
                r"smbv1\s+.*enabled",
                r"smb1\s+.*protocol\s+.*enabled"
            ],
            "suggestion": "Disable SMBv1 via Windows Features or PowerShell."
        },
        {
            "rule": "Ensure automatic updates are enabled",
            "pass_patterns": [
                r"automatic\s+.*updates\s+.*enabled",
                r"windows\s+.*update\s+.*auto\s+.*download",
                r"autoupdate\s+.*on"
            ],
            "fail_patterns": [
                r"automatic\s+.*updates\s+.*disabled",
                r"windows\s+.*update\s+.*auto\s+.*off"
            ],
            "suggestion": "Enable auto-updates in Settings > Windows Update."
        },
        {
            "rule": "Ensure antivirus is enabled",
            "pass_patterns": [
                r"windows\s+.*defender\s+.*enabled",
                r"antivirus\s+.*enabled",
                r"real-time\s+.*protection\s+.*on"
            ],
            "fail_patterns": [
                r"windows\s+.*defender\s+.*disabled",
                r"antivirus\s+.*disabled",
                r"real-time\s+.*protection\s+.*off"
            ],
            "suggestion": "Enable Windows Defender or another antivirus solution."
        },
        {
            "rule": "Ensure Remote Desktop is disabled",
            "pass_patterns": [
                r"remote\s+.*desktop\s+.*enabled\s*:\s*no",
                r"rdp\s+.*disabled",
                r"remote\s+.*desktop\s+.*off"
            ],
            "fail_patterns": [
                r"remote\s+.*desktop\s+.*enabled\s*:\s*yes",
                r"rdp\s+.*enabled"
            ],
            "suggestion": "Disable RDP via System Properties > Remote Settings."
        },
        {
            "rule": "Ensure Windows Hello is enabled",
            "pass_patterns": [
                r"windows\s+.*hello\s+.*enabled",
                r"hello\s+.*biometric\s+.*authentication\s+.*enabled",
                r"hello\s+.*login\s+.*enabled"
            ],
            "fail_patterns": [
                r"windows\s+.*hello\s+.*disabled",
                r"hello\s+.*not\s+.*configured"
            ],
            "suggestion": "Enable Windows Hello under Sign-in options in Settings."
        },
        {
            "rule": "Ensure screen lock is configured",
            "pass_patterns": [
                r"screen\s+.*lock\s+.*timeout\s*:\s*\d+",
                r"lock\s+.*screen\s+.*enabled",
                r"idle\s+.*lock\s+.*enabled"
            ],
            "fail_patterns": [
                r"screen\s+.*lock\s+.*disabled",
                r"idle\s+.*lock\s+.*off"
            ],
            "suggestion": "Set screen timeout in Settings > Power & Sleep."
        },
        {
            "rule": "Ensure secure boot is enabled",
            "pass_patterns": [
                r"secure\s+.*boot\s+.*state\s*:\s*on",
                r"secure\s+.*boot\s+.*enabled",
                r"firmware\s+.*secure\s+.*boot"
            ],
            "fail_patterns": [
                r"secure\s+.*boot\s+.*state\s*:\s*off",
                r"secure\s+.*boot\s+.*disabled"
            ],
            "suggestion": "Enable secure boot in BIOS/UEFI settings."
        },
        {
            "rule": "Ensure Windows Defender Exploit Guard is enabled",
            "pass_patterns": [
                r"exploit\s+.*guard\s+.*enabled",
                r"windows\s+.*defender\s+.*exploit\s+.*protection",
                r"eg\s+.*enabled"
            ],
            "fail_patterns": [
                r"exploit\s+.*guard\s+.*disabled",
                r"eg\s+.*disabled"
            ],
            "suggestion": "Enable Exploit Guard via Group Policy."
        }
    ]

    for rule in windows11_rules:
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
                if re.search(pat, text):
                    found_fail = True
                    matched_indices.add(idx)
                    break
            if found_fail:
                break

            for pat in rule["pass_patterns"]:
                if re.search(pat, text):
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

    # Unrecognized line check
    all_patterns = [pat for r in windows11_rules for pat in (r["pass_patterns"] + r["fail_patterns"])]
    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
