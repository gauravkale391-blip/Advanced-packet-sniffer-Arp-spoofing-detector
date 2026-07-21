def generate_investigation_summary(entry, mitre_info):
    ip = entry["IP Address"]
    mac_count = entry["MAC Count"]
    macs = entry["MAC Address(es)"]

    if mac_count >= 3:
        threat_level = "Critical"
        reason = f"IP {ip} is associated with {mac_count} different MAC addresses — a strong indicator of active ARP spoofing or a compromised network segment."
        action = f"Immediately isolate {ip} from the network, verify with the legitimate device owner, and inspect switch ARP tables for anomalies."
    elif mac_count == 2:
        threat_level = "High"
        reason = f"IP {ip} shows two conflicting MAC addresses ({macs}), which typically indicates a spoofing attempt is in progress."
        action = f"Investigate both devices claiming IP {ip}. Confirm the legitimate device, and consider temporarily blocking the suspicious MAC address."
    else:
        threat_level = "Low"
        reason = f"IP {ip} shows minor MAC inconsistency, which could be a false positive from device roaming or DHCP changes."
        action = "Monitor for recurrence before taking action."

    summary = f"""
**Threat Level:** {threat_level}

**Reason:**
{reason}

**MITRE Context:**
This activity aligns with {mitre_info['technique']} ({mitre_info['name']}), under the {mitre_info['tactic']} tactic(s).

**Recommended Action:**
{action}

**Note:** This is an automated assessment. Final action must be confirmed by a human SOC analyst.
"""
    return summary
