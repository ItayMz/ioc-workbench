export const DEFENDER_CATEGORIES = [
  'Collection',
  'CommandAndControl',
  'CredentialAccess',
  'DefenseEvasion',
  'Discovery',
  'Execution',
  'Exfiltration',
  'Exploit',
  'InitialAccess',
  'LateralMovement',
  'Malware',
  'Persistence',
  'PrivilegeEscalation',
  'Ransomware',
  'SuspiciousActivity',
  'UnwantedSoftware',
]

export const DEFAULT_DEFENDER_CATEGORY = 'Malware'

export function normalizeDefaultCategory(value) {
  const normalized = String(value || '').trim()
  if (!normalized) {
    return DEFAULT_DEFENDER_CATEGORY
  }

  return DEFENDER_CATEGORIES.includes(normalized)
    ? normalized
    : DEFAULT_DEFENDER_CATEGORY
}
