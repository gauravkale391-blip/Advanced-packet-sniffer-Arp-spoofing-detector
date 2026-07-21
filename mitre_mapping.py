MITRE_DATABASE = {
    "ARP_SPOOFING": {
        "technique": "T1557.002",
        "name": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "tactic": "Credential Access, Collection",
        "description": "An attacker sends falsified ARP messages to associate their MAC address with the IP address of another host, redirecting traffic through the attacker's machine.",
        "mitigation": "Enable Dynamic ARP Inspection (DAI) on network switches, use static ARP entries for critical hosts, and monitor for duplicate IP-to-MAC mappings."
    },
    "UNKNOWN": {
        "technique": "Unknown",
        "name": "Unclassified activity",
        "tactic": "Unknown",
        "description": "This alert type has not been mapped to a MITRE ATT&CK technique yet.",
        "mitigation": "Manual review recommended."
    }
}


def get_mitre_info(attack_type="ARP_SPOOFING"):
    return MITRE_DATABASE.get(attack_type, MITRE_DATABASE["UNKNOWN"])
