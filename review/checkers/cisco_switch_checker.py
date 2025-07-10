import re

cisco_switch_rules = [
    {
        "rule": "Disable HTTP server",
        "pass_patterns": [r"no\s+.*ip\s+.*http\s+.*server", r"http\s+.*server\s+.*disable", r"disable\s+.*http\s+.*server"],
        "fail_patterns": [r"ip\s+.*http\s+.*server", r"http\s+.*server\s+.*enable"],
        "suggestion": "Disable HTTP server using: no ip http server"
    },
    {
        "rule": "Disable HTTPS server",
        "pass_patterns": [r"no\s+.*ip\s+.*http\s+.*secure-server", r"https\s+.*server\s+.*disable", r"disable\s+.*https\s+.*server"],
        "fail_patterns": [r"ip\s+.*http\s+.*secure-server"],
        "suggestion": "Disable HTTPS server using: no ip http secure-server"
    },
    {
        "rule": "Disable unused services",
        "pass_patterns": [r"no\s+.*service\s+.*finger", r"no\s+.*service\s+.*pads", r"no\s+.*service\s+.*tcp-small-servers"],
        "fail_patterns": [r"service\s+.*finger", r"service\s+.*pads"],
        "suggestion": "Disable unused services: finger, tcp-small-servers, etc."
    },
    {
        "rule": "Enable SSH version 2",
        "pass_patterns": [r"ip\s+.*ssh\s+.*version\s+.*2", r"ssh\s+.*version\s+.*2"],
        "fail_patterns": [r"ip\s+.*ssh\s+.*version\s+.*1"],
        "suggestion": "Enable SSH v2 using: ip ssh version 2"
    },
    {
        "rule": "Configure login banner",
        "pass_patterns": [r"banner\s+.*login", r"banner\s+.*exec", r"login\s+.*banner"],
        "fail_patterns": [r"no\s+.*banner"],
        "suggestion": "Configure login banner to warn unauthorized users"
    },
    {
        "rule": "Set password encryption",
        "pass_patterns": [r"service\s+.*password-encryption", r"enable\s+.*password\s+.*encryption"],
        "fail_patterns": [r"no\s+.*service\s+.*password-encryption"],
        "suggestion": "Encrypt passwords using: service password-encryption"
    },
    {
        "rule": "Enable AAA authentication",
        "pass_patterns": [r"aaa\s+.*new-model", r"aaa\s+.*authentication", r"enable\s+.*aaa"],
        "fail_patterns": [r"no\s+.*aaa", r"aaa\s+.*disabled"],
        "suggestion": "Enable AAA using: aaa new-model"
    },
    {
        "rule": "Set exec-timeout",
        "pass_patterns": [r"exec-timeout\s+.*\d+", r"timeout\s+.*exec"],
        "fail_patterns": [r"exec-timeout\s+.*0"],
        "suggestion": "Set exec timeout to log out idle sessions"
    },
    {
        "rule": "Disable CDP on unused interfaces",
        "pass_patterns": [r"no\s+.*cdp\s+.*enable"],
        "fail_patterns": [r"cdp\s+.*enable"],
        "suggestion": "Disable CDP on unused interfaces"
    },
    {
        "rule": "Disable unused interfaces",
        "pass_patterns": [r"interface\s+.*\s+.*\s+.*shutdown", r"shutdown\s+.*interface"],
        "fail_patterns": [r"no\s+.*shutdown"],
        "suggestion": "Shutdown unused interfaces to prevent unauthorized access"
    },
    {
        "rule": "Enable port security",
        "pass_patterns": [r"switchport\s+.*port-security", r"enable\s+.*port\s+.*security"],
        "fail_patterns": [r"no\s+.*switchport\s+.*port-security"],
        "suggestion": "Enable port security on access ports"
    },
    {
        "rule": "Set port security max MAC",
        "pass_patterns": [r"switchport\s+.*port-security\s+.*maximum\s+.*\d+", r"port-security\s+.*max"],
        "fail_patterns": [],
        "suggestion": "Limit number of MAC addresses using: switchport port-security maximum"
    },
    {
        "rule": "Enable port security violation mode",
        "pass_patterns": [r"switchport\s+.*port-security\s+.*violation\s+.*(restrict|shutdown|protect)"],
        "fail_patterns": [],
        "suggestion": "Set violation mode to restrict/shutdown/protect"
    },
    {
        "rule": "Enable DHCP snooping",
        "pass_patterns": [r"ip\s+.*dhcp\s+.*snooping", r"enable\s+.*dhcp\s+.*snooping"],
        "fail_patterns": [r"no\s+.*ip\s+.*dhcp\s+.*snooping"],
        "suggestion": "Enable DHCP snooping to prevent rogue DHCP"
    },
    {
        "rule": "Enable Dynamic ARP Inspection (DAI)",
        "pass_patterns": [r"ip\s+.*arp\s+.*inspection", r"dynamic\s+.*arp\s+.*inspection"],
        "fail_patterns": [],
        "suggestion": "Enable DAI to prevent ARP spoofing"
    },
    {
        "rule": "Enable BPDU guard",
        "pass_patterns": [r"spanning-tree\s+.*bpduguard\s+.*enable", r"bpdu\s+.*guard\s+.*enable"],
        "fail_patterns": [],
        "suggestion": "Enable BPDU Guard on edge ports"
    },
    {
        "rule": "Enable Root Guard",
        "pass_patterns": [r"spanning-tree\s+.*guard\s+.*root", r"enable\s+.*root\s+.*guard"],
        "fail_patterns": [],
        "suggestion": "Use Root Guard to enforce spanning-tree root"
    },
    {
        "rule": "Disable VTP on switches",
        "pass_patterns": [r"vtp\s+.*mode\s+.*transparent", r"disable\s+.*vtp"],
        "fail_patterns": [r"vtp\s+.*mode\s+.*server"],
        "suggestion": "Set VTP mode to transparent to avoid unwanted changes"
    },
    {
        "rule": "Enable logging",
        "pass_patterns": [r"logging\s+.*buffered", r"logging\s+.*console", r"logging\s+.*monitor"],
        "fail_patterns": [r"no\s+.*logging"],
        "suggestion": "Enable logging to monitor events"
    },
    {
        "rule": "Limit login attempts",
        "pass_patterns": [r"login\s+.*block-for", r"login\s+.*attempts"],
        "fail_patterns": [],
        "suggestion": "Limit failed login attempts using: login block-for"
    }
]

def check_rules(config_lines):
    results = []
    config = "\n".join(config_lines)
    matched_lines = set()

    for rule in cisco_switch_rules:
        passed = any(re.search(p, config, re.IGNORECASE) for p in rule["pass_patterns"])
        failed = any(re.search(p, config, re.IGNORECASE) for p in rule["fail_patterns"])
        matched = passed or failed

        if passed:
            results.append(("Pass", rule["rule"], "-"))
        elif failed:
            results.append(("Fail", rule["rule"], rule["suggestion"]))
        else:
            results.append(("Missing", rule["rule"], "No configuration provided for this rule."))

        if matched:
            for pattern in rule["pass_patterns"] + rule["fail_patterns"]:
                for line in config_lines:
                    if re.search(pattern, line, re.IGNORECASE):
                        matched_lines.add(line.strip())

    for line in config_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped not in matched_lines:
            results.append(("Unrecognized", stripped, "No matching benchmark rule for this configuration."))

    return results
