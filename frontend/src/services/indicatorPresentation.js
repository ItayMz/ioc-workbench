export const DETECTED_EMPTY_MESSAGE = 'No supported IOCs were detected.'
export const INDICATOR_COPY_ERROR_MESSAGE = 'Unable to copy indicators. Please try again.'
export const INDICATOR_DISPLAY_MODE = {
  REFANGED: 'refanged',
  ORIGINAL: 'original',
}

export const INDICATOR_WORKFLOW_MODE = {
  DEFENDER: 'defender',
  CROWDSTRIKE: 'crowdstrike',
}

const DEFENDER_HANDLED_LABELS = new Set(['IPv4', 'IPv6', 'Domains', 'URLs', 'MD5', 'SHA1', 'SHA256'])
const DEFENDER_CUSTOMER_LABELS = new Set(['Sender Email Addresses'])
const CROWDSTRIKE_HANDLED_LABELS = new Set(['IPv4', 'MD5', 'SHA256'])
const CROWDSTRIKE_CUSTOMER_LABELS = new Set(['Domains', 'URLs', 'Sender Email Addresses'])

const GROUP_DEFINITIONS = [
  { label: 'MD5', types: ['filemd5', 'md5'] },
  { label: 'SHA1', types: ['filesha1', 'sha1'] },
  { label: 'SHA256', types: ['filesha256', 'sha256'] },
  { label: 'IPv4', types: ['ipv4'] },
  { label: 'IPv6', types: ['ipv6'] },
  { label: 'Domains', types: ['domainname', 'domain', 'domains'] },
  { label: 'URLs', types: ['url', 'urls'] },
  {
    label: 'Sender Email Addresses',
    types: ['senderemailaddress', 'sender_email_address', 'email', 'senderemail'],
  },
]

function normalizeIndicatorType(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
}

function hasKnownType(ioc) {
  const type = String(ioc?.indicator_type || '').trim()
  if (!type) {
    return false
  }

  const lowered = type.toLowerCase()
  return lowered !== 'n/a' && lowered !== 'unknown'
}

export function getDetectedIndicators(indicators) {
  const detected = []

  for (const ioc of indicators || []) {
    const isDetected = Boolean(ioc?.valid) && hasKnownType(ioc)

    if (isDetected) {
      detected.push(ioc)
    }
  }

  return detected
}

export function getIndicatorDisplayValue(ioc, mode) {
  if (mode === INDICATOR_DISPLAY_MODE.ORIGINAL) {
    return ioc?.original_value || ''
  }

  return ioc?.refanged_value || ioc?.original_value || ''
}

export function getGroupValues(group, mode) {
  return (group?.items || []).map((ioc) => getIndicatorDisplayValue(ioc, mode))
}

export function getInitialExpandedGroups(groups) {
  const expandedGroups = {}

  for (const group of groups || []) {
    expandedGroups[group.label] = false
  }

  return expandedGroups
}

export function syncExpandedGroups(currentExpandedGroups, groups) {
  const synced = {}

  for (const group of groups || []) {
    if (Object.hasOwn(currentExpandedGroups || {}, group.label)) {
      synced[group.label] = Boolean(currentExpandedGroups[group.label])
      continue
    }

    synced[group.label] = false
  }

  return synced
}

export function toggleGroupExpanded(expandedGroups, groupLabel) {
  return {
    ...expandedGroups,
    [groupLabel]: !expandedGroups?.[groupLabel],
  }
}

export function buildGroupCopyPayload(group, mode) {
  return getGroupValues(group, mode).join('\n')
}

function getWorkflowLabelRules(workflowMode) {
  if (workflowMode === INDICATOR_WORKFLOW_MODE.CROWDSTRIKE) {
    return {
      handled: CROWDSTRIKE_HANDLED_LABELS,
      customer: CROWDSTRIKE_CUSTOMER_LABELS,
    }
  }

  return {
    handled: DEFENDER_HANDLED_LABELS,
    customer: DEFENDER_CUSTOMER_LABELS,
  }
}

export function splitIndicatorGroupsByHandling(groups, workflowMode = INDICATOR_WORKFLOW_MODE.DEFENDER) {
  const { handled, customer } = getWorkflowLabelRules(workflowMode)
  const handledByUs = []
  const customerAction = []
  const investigationOnly = []

  for (const group of groups || []) {
    if (handled.has(group.label)) {
      handledByUs.push(group)
      continue
    }

    if (customer.has(group.label)) {
      customerAction.push(group)
      continue
    }

    investigationOnly.push(group)
  }

  return {
    handledByUs,
    customerAction,
    investigationOnly,
  }
}

export function buildHandlingCopyPayload(groups, mode, workflowMode, target) {
  const split = splitIndicatorGroupsByHandling(groups, workflowMode)
  const sourceGroups = target === 'customerAction' ? split.customerAction : split.handledByUs
  const groupBlocks = []

  for (const group of sourceGroups) {
    const values = getGroupValues(group, mode).filter(Boolean)
    if (!values.length) {
      continue
    }

    groupBlocks.push(`${group.label} (${values.length}):\n\n${values.join('\n')}`)
  }

  return groupBlocks.join('\n\n')
}

export function getGroupCopySuccessMessage(groupLabel, count) {
  return `Copied ${count} ${groupLabel}.`
}

export function getHandlingCopySuccessMessage(totalCount, handlingLabel) {
  return `Copied ${totalCount} indicators for ${handlingLabel}.`
}

export function groupDetectedIndicatorsByType(detectedIndicators) {
  const groups = GROUP_DEFINITIONS.map((definition) => ({
    label: definition.label,
    items: [],
  }))

  for (const ioc of detectedIndicators || []) {
    const normalizedType = normalizeIndicatorType(ioc?.indicator_type)
    let groupIndex = GROUP_DEFINITIONS.findIndex((definition) => definition.types.includes(normalizedType))

    if (groupIndex === -1 && (normalizedType === 'ipaddress' || normalizedType === 'ip')) {
      const indicatorValue = getIndicatorDisplayValue(ioc, INDICATOR_DISPLAY_MODE.REFANGED)
      groupIndex = indicatorValue.includes(':') ? 4 : 3
    }

    if (groupIndex >= 0) {
      groups[groupIndex].items.push(ioc)
    }
  }

  return groups.filter((group) => group.items.length > 0)
}

