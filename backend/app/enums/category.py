from enum import Enum


class Category(str, Enum):
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "CommandAndControl"
    CREDENTIAL_ACCESS = "CredentialAccess"
    DEFENSE_EVASION = "DefenseEvasion"
    DISCOVERY = "Discovery"
    EXECUTION = "Execution"
    EXFILTRATION = "Exfiltration"
    EXPLOIT = "Exploit"
    INITIAL_ACCESS = "InitialAccess"
    LATERAL_MOVEMENT = "LateralMovement"
    MALWARE = "Malware"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    RANSOMWARE = "Ransomware"
    SUSPICIOUS_ACTIVITY = "SuspiciousActivity"
    UNWANTED_SOFTWARE = "UnwantedSoftware"
