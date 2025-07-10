import re

windows_server_2019_rules = [
    {
        "rule": "Ensure Windows Defender Antivirus is enabled",
        "pass_patterns": [r"windows\s+.*defender\s+.*antivirus\s+.*enabled", r"real-time\s+.*protection\s+.*on", r"defender\s+.*status\s+.*active"],
        "fail_patterns": [r"windows\s+.*defender\s+.*antivirus\s+.*disabled", r"defender\s+.*status\s+.*inactive"],
        "suggestion": "Enable Windows Defender from Windows Security settings or PowerShell."
    },
    {
        "rule": "Ensure password complexity is enabled",
        "pass_patterns": [r"password\s+.*complexity\s+.*enabled", r"password\s+.*must\s+.*meet\s+.*complexity\s+.*requirements\s*:\s*enabled", r"complex\s+.*password\s+.*policy"],
        "fail_patterns": [r"password\s+.*complexity\s+.*disabled", r"password\s+.*complexity\s+.*off"],
        "suggestion": "Set password complexity via Group Policy: Computer Config > Policies > Windows Settings > Security Settings > Account Policies > Password Policy."
    },
    {
        "rule": "Ensure minimum password length is 14 or more",
        "pass_patterns": [r"minimum\s+.*password\s+.*length\s*:\s*(1[4-9]|\d{3,})", r"password\s+.*length\s+.*min\s*14"],
        "fail_patterns": [r"minimum\s+.*password\s+.*length\s*:\s*([0-9]|1[0-3])", r"password\s+.*length\s+.*min\s*([0-9]|1[0-3])"],
        "suggestion": "Set minimum password length via Local Security Policy."
    },
    {
        "rule": "Ensure account lockout threshold is set to 5 or fewer",
        "pass_patterns": [r"account\s+.*lockout\s+.*threshold\s*:\s*[1-5]", r"lockout\s+.*after\s+.*[1-5]\s+.*attempts"],
        "fail_patterns": [r"account\s+.*lockout\s+.*threshold\s*:\s*[6-9]", r"lockout\s+.*after\s+.*[6-9]\s+.*attempts"],
        "suggestion": "Configure account lockout threshold via Group Policy."
    },
    {
        "rule": "Ensure guest account is disabled",
        "pass_patterns": [r"guest\s+.*account\s+.*disabled", r"disable\s+.*guest\s+.*user", r"no\s+.*guest\s+.*logon"],
        "fail_patterns": [r"guest\s+.*account\s+.*enabled", r"enable\s+.*guest\s+.*user"],
        "suggestion": "Disable guest account via Local Users and Groups or GPO."
    },
    {
        "rule": "Ensure administrator account is renamed",
        "pass_patterns": [r"rename\s+.*administrator\s+.*account", r"admin\s+.*account\s+.*renamed", r"default\s+.*admin\s+.*renamed"],
        "fail_patterns": [r"default\s+.*admin\s+.*name", r"administrator\s+.*account\s+.*default"],
        "suggestion": "Use Group Policy to rename the Administrator account."
    },
    {
        "rule": "Ensure 'Audit Logon Events' is configured",
        "pass_patterns": [r"audit\s+.*logon\s+.*events\s+.*enabled", r"logon\s+.*success\s+.*audit", r"logon\s+.*failure\s+.*audit"],
        "fail_patterns": [r"audit\s+.*logon\s+.*events\s+.*disabled"],
        "suggestion": "Enable logon event auditing via GPO > Advanced Audit Policy Configuration."
    },
    {
        "rule": "Ensure 'Audit Object Access' is enabled",
        "pass_patterns": [r"audit\s+.*object\s+.*access\s+.*enabled", r"object\s+.*access\s+.*auditing"],
        "fail_patterns": [r"audit\s+.*object\s+.*access\s+.*disabled"],
        "suggestion": "Enable object access auditing using Group Policy."
    },
    {
        "rule": "Ensure 'Windows Firewall' is enabled for all profiles",
        "pass_patterns": [r"firewall\s+.*domain\s+.*enabled", r"firewall\s+.*private\s+.*enabled", r"firewall\s+.*public\s+.*enabled"],
        "fail_patterns": [r"firewall\s+.*disabled"],
        "suggestion": "Enable firewall using Control Panel or `netsh`."
    },
    {
        "rule": "Ensure 'Remote Desktop' is disabled",
        "pass_patterns": [r"remote\s+.*desktop\s+.*disabled", r"rdp\s+.*not\s+.*enabled"],
        "fail_patterns": [r"remote\s+.*desktop\s+.*enabled", r"rdp\s+.*enabled"],
        "suggestion": "Turn off RDP in System Properties or Group Policy."
    },
    {
        "rule": "Ensure Network Level Authentication is required",
        "pass_patterns": [r"nla\s+.*required", r"network\s+.*level\s+.*auth\s+.*enabled"],
        "fail_patterns": [r"nla\s+.*not\s+.*required", r"network\s+.*level\s+.*auth\s+.*disabled"],
        "suggestion": "Require NLA for RDP via System Properties or GPO."
    },
    {
        "rule": "Ensure SMBv1 is disabled",
        "pass_patterns": [r"smbv1\s+.*disabled", r"smb1\s+.*protocol\s+.*off"],
        "fail_patterns": [r"smbv1\s+.*enabled", r"smb1\s+.*protocol\s+.*on"],
        "suggestion": "Disable SMBv1 via PowerShell: `Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol`"
    },
    {
        "rule": "Ensure 'Windows Update' is enabled",
        "pass_patterns": [r"windows\s+.*update\s+.*enabled", r"automatic\s+.*updates\s+.*on", r"update\s+.*service\s+.*running"],
        "fail_patterns": [r"windows\s+.*update\s+.*disabled", r"automatic\s+.*updates\s+.*off"],
        "suggestion": "Enable Windows Update from Settings or GPO."
    },
    {
        "rule": "Ensure 'Windows Defender SmartScreen' is enabled",
        "pass_patterns": [r"smartscreen\s+.*enabled", r"smartscreen\s+.*filter\s+.*on"],
        "fail_patterns": [r"smartscreen\s+.*disabled", r"smartscreen\s+.*filter\s+.*off"],
        "suggestion": "Enable SmartScreen in Windows Defender settings."
    },
    {
        "rule": "Ensure Windows Defender Application Guard is enabled",
        "pass_patterns": [r"application\s+.*guard\s+.*enabled", r"windows\s+.*defender\s+.*application\s+.*guard"],
        "fail_patterns": [r"application\s+.*guard\s+.*disabled"],
        "suggestion": "Enable from Features > Windows Defender Application Guard."
    },
    {
        "rule": "Ensure security updates are automatically installed",
        "pass_patterns": [r"auto\s+.*install\s+.*security\s+.*updates", r"security\s+.*updates\s+.*enabled"],
        "fail_patterns": [r"auto\s+.*install\s+.*security\s+.*updates\s+.*disabled"],
        "suggestion": "Configure via Windows Update settings or GPO."
    },
    {
        "rule": "Ensure TLS 1.2 is enabled",
        "pass_patterns": [r"tls\s+.*1\.2\s+.*enabled", r"secure\s+.*protocol\s+.*tls12"],
        "fail_patterns": [r"tls\s+.*1\.2\s+.*disabled"],
        "suggestion": "Enable TLS 1.2 in registry: `HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client`."
    },
    {
        "rule": "Ensure Anonymous SID Enumeration is disabled",
        "pass_patterns": [r"anonymous\s+.*sid\s+.*enumeration\s+.*disabled", r"restrict\s+.*anonymous\s+.*sid"],
        "fail_patterns": [r"anonymous\s+.*sid\s+.*enumeration\s+.*enabled"],
        "suggestion": "Disable using registry or GPO."
    },
    {
        "rule": "Ensure ICMP redirects are not accepted",
        "pass_patterns": [r"icmp\s+.*redirects\s+.*disabled", r"no\s+.*icmp\s+.*redirect"],
        "fail_patterns": [r"icmp\s+.*redirects\s+.*enabled"],
        "suggestion": "Use `netsh int ipv4 set global icmpredirects=disabled`."
    },
    {
        "rule": "Ensure 'Ctrl+Alt+Del' is required at logon",
        "pass_patterns": [r"ctrl\s*\+\s*alt\s*\+\s*del\s*required", r"secure\s+.*logon\s+.*enabled"],
        "fail_patterns": [r"ctrl\s*\+\s*alt\s*\+\s*del\s*not\s*required", r"secure\s+.*logon\s+.*disabled"],
        "suggestion": "Enable this from Local Security Policy > Interactive Logon."
    }
]

def check_rules(config_lines):
    results = []
    matched_indices = set()
    normalized = [line.rstrip('\n') for line in config_lines]

    for rule in windows_server_2019_rules:
        name = rule["rule"]
        suggestion = rule["suggestion"]
        found_pass = False
        found_fail = False

        for idx, raw in enumerate(normalized):
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('!'):
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

    # Identify unrecognized lines
    all_patterns = [pat for rule in windows_server_2019_rules for pat in (rule["pass_patterns"] + rule["fail_patterns"])]

    for idx, raw in enumerate(normalized):
        if idx in matched_indices:
            continue
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('!'):
            continue
        if not any(re.search(pat, line.lower()) for pat in all_patterns):
            results.append((line, "Unrecognized", "No matching benchmark rule for this configuration."))

    return results
