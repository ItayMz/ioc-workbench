import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildHandlingCopyPayload,
  buildGroupCopyPayload,
  DETECTED_EMPTY_MESSAGE,
  getHandlingCopySuccessMessage,
  getGroupCopySuccessMessage,
  getDetectedIndicators,
  getInitialExpandedGroups,
  getIndicatorDisplayValue,
  INDICATOR_WORKFLOW_MODE,
  INDICATOR_COPY_ERROR_MESSAGE,
  groupDetectedIndicatorsByType,
  getGroupValues,
  INDICATOR_DISPLAY_MODE,
  splitIndicatorGroupsByHandling,
  syncExpandedGroups,
  toggleGroupExpanded,
} from './indicatorPresentation.js'

test('main table input includes only valid supported indicators', () => {
  const detected = getDetectedIndicators([
    {
      original_value: 'https://good.example',
      refanged_value: 'https://good.example',
      indicator_type: 'Url',
      valid: true,
    },
    {
      original_value: 'freeform text',
      refanged_value: 'freeform text',
      indicator_type: null,
      valid: false,
      reason: 'unsupported_indicator',
    },
    {
      original_value: 'unknown-value',
      refanged_value: 'unknown-value',
      indicator_type: 'N/A',
      valid: true,
    },
  ])

  assert.equal(detected.length, 1)
  assert.equal(detected[0].indicator_type, 'Url')
})

test('no valid IOCs uses the expected empty-state message', () => {
  const detected = getDetectedIndicators([
    {
      original_value: 'hello world',
      refanged_value: 'hello world',
      indicator_type: null,
      valid: false,
      reason: 'unsupported_indicator',
    },
  ])

  assert.equal(detected.length, 0)
  assert.equal(DETECTED_EMPTY_MESSAGE, 'No supported IOCs were detected.')
})

test('detected indicators are grouped by IOC type in display order and preserve original order within each group', () => {
  const grouped = groupDetectedIndicatorsByType([
    { indicator_type: 'FileSha1', refanged_value: 'sha1-A', original_value: 'sha1-A', valid: true },
    { indicator_type: 'IpAddress', refanged_value: '8.8.8.8', original_value: '8.8.8.8', valid: true },
    { indicator_type: 'IpAddress', refanged_value: '2001:db8::1', original_value: '2001:db8::1', valid: true },
    { indicator_type: 'DomainName', refanged_value: 'domain-A', original_value: 'domain-A', valid: true },
    { indicator_type: 'FileSha1', refanged_value: 'sha1-B', original_value: 'sha1-B', valid: true },
    { indicator_type: 'Url', refanged_value: 'url-A', original_value: 'url-A', valid: true },
  ])

  assert.deepEqual(grouped.map((group) => group.label), ['SHA1', 'IPv4', 'IPv6', 'Domains', 'URLs'])
  assert.deepEqual(grouped[0].items.map((item) => item.refanged_value), ['sha1-A', 'sha1-B'])
  assert.equal(grouped[0].items.length, 2)
  assert.equal(grouped[1].items.length, 1)
  assert.equal(grouped[2].items.length, 1)
  assert.equal(grouped[3].items.length, 1)
  assert.equal(grouped[4].items.length, 1)
})

test('empty IOC groups are hidden and sender email addresses are grouped when present', () => {
  const grouped = groupDetectedIndicatorsByType([
    {
      indicator_type: 'SenderEmailAddress',
      refanged_value: 'user@example.com',
      original_value: 'user@example.com',
      valid: true,
    },
  ])

  assert.equal(grouped.length, 1)
  assert.equal(grouped[0].label, 'Sender Email Addresses')
})

test('default display mode uses refanged values and switching to original updates all groups', () => {
  const ioc = {
    original_value: 'hxxps://example[.]com/path',
    refanged_value: 'https://example.com/path',
  }

  assert.equal(
    getIndicatorDisplayValue(ioc, INDICATOR_DISPLAY_MODE.REFANGED),
    'https://example.com/path',
  )
  assert.equal(
    getIndicatorDisplayValue(ioc, INDICATOR_DISPLAY_MODE.ORIGINAL),
    'hxxps://example[.]com/path',
  )
})

test('accordion defaults to all groups collapsed', () => {
  const groups = [
    { label: 'MD5', items: [{ original_value: 'a', refanged_value: 'a' }] },
    { label: 'Domains', items: [{ original_value: 'd', refanged_value: 'd' }] },
  ]

  const expanded = getInitialExpandedGroups(groups)
  assert.equal(expanded.MD5, false)
  assert.equal(expanded.Domains, false)
})

test('accordion expand and collapse toggles only targeted group', () => {
  const next = toggleGroupExpanded({ Domains: true, SHA256: false }, 'SHA256')

  assert.equal(next.Domains, true)
  assert.equal(next.SHA256, true)
})

test('accordion expansion state persists when groups are synced with new data', () => {
  const synced = syncExpandedGroups(
    { Domains: false, SHA256: true },
    [
      { label: 'Domains', items: [] },
      { label: 'SHA256', items: [] },
      { label: 'MD5', items: [] },
    ],
  )

  assert.equal(synced.Domains, false)
  assert.equal(synced.SHA256, true)
  assert.equal(synced.MD5, false)
})

test('group value resolution and per-group copy respect display mode', () => {
  const group = {
    label: 'Domains',
    items: [
      { original_value: 'example[.]com', refanged_value: 'example.com' },
      { original_value: 'mail[.]example[.]com', refanged_value: 'mail.example.com' },
    ],
  }

  assert.deepEqual(getGroupValues(group, INDICATOR_DISPLAY_MODE.REFANGED), ['example.com', 'mail.example.com'])
  assert.deepEqual(getGroupValues(group, INDICATOR_DISPLAY_MODE.ORIGINAL), ['example[.]com', 'mail[.]example[.]com'])
  assert.equal(buildGroupCopyPayload(group, INDICATOR_DISPLAY_MODE.ORIGINAL), 'example[.]com\nmail[.]example[.]com')
  assert.equal(buildGroupCopyPayload(group, INDICATOR_DISPLAY_MODE.REFANGED), 'example.com\nmail.example.com')
})

test('workflow clipboard payload for Defender preserves group and IOC ordering and respects mode', () => {
  const groups = [
    {
      label: 'Domains',
      items: [
        { original_value: 'a[.]com', refanged_value: 'a.com' },
        { original_value: 'b[.]com', refanged_value: 'b.com' },
      ],
    },
    {
      label: 'SHA256',
      items: [
        { original_value: 'orig-hash', refanged_value: 'ref-hash' },
      ],
    },
    {
      label: 'MD5',
      items: [
        { original_value: 'orig-md5', refanged_value: 'ref-md5' },
      ],
    },
    {
      label: 'Sender Email Addresses',
      items: [
        { original_value: 'user@example.com', refanged_value: 'user@example.com' },
      ],
    },
  ]

  assert.equal(
    buildHandlingCopyPayload(groups, INDICATOR_DISPLAY_MODE.REFANGED, INDICATOR_WORKFLOW_MODE.DEFENDER, 'handledByUs'),
    'Domains (2):\n\na.com\nb.com\n\nSHA256 (1):\n\nref-hash\n\nMD5 (1):\n\nref-md5',
  )
  assert.equal(
    buildHandlingCopyPayload(groups, INDICATOR_DISPLAY_MODE.ORIGINAL, INDICATOR_WORKFLOW_MODE.DEFENDER, 'handledByUs'),
    'Domains (2):\n\na[.]com\nb[.]com\n\nSHA256 (1):\n\norig-hash\n\nMD5 (1):\n\norig-md5',
  )
  assert.equal(
    buildHandlingCopyPayload(groups, INDICATOR_DISPLAY_MODE.ORIGINAL, INDICATOR_WORKFLOW_MODE.DEFENDER, 'customerAction'),
    'Sender Email Addresses (1):\n\nuser@example.com',
  )
})

test('CrowdStrike clipboard grouping excludes SHA1 from handled and customer buckets', () => {
  const groups = [
    {
      label: 'SHA1',
      items: [
        { original_value: 'sha1-orig', refanged_value: 'sha1-ref' },
      ],
    },
    {
      label: 'SHA256',
      items: [
        { original_value: 'sha256-orig', refanged_value: 'sha256-ref' },
      ],
    },
    {
      label: 'URLs',
      items: [
        { original_value: 'hxxps://x[.]com', refanged_value: 'https://x.com' },
      ],
    },
  ]

  const split = splitIndicatorGroupsByHandling(groups, INDICATOR_WORKFLOW_MODE.CROWDSTRIKE)
  assert.deepEqual(split.handledByUs.map((group) => group.label), ['SHA256'])
  assert.deepEqual(split.customerAction.map((group) => group.label), ['URLs'])
  assert.deepEqual(split.investigationOnly.map((group) => group.label), ['SHA1'])

  assert.equal(
    buildHandlingCopyPayload(groups, INDICATOR_DISPLAY_MODE.REFANGED, INDICATOR_WORKFLOW_MODE.CROWDSTRIKE, 'handledByUs'),
    'SHA256 (1):\n\nsha256-ref',
  )
  assert.equal(
    buildHandlingCopyPayload(groups, INDICATOR_DISPLAY_MODE.ORIGINAL, INDICATOR_WORKFLOW_MODE.CROWDSTRIKE, 'customerAction'),
    'URLs (1):\n\nhxxps://x[.]com',
  )
})

test('workflow clipboard payload uses one blank line after each header and between groups while omitting empty-value groups', () => {
  const groups = [
    {
      label: 'MD5',
      items: [
        { original_value: 'a-md5', refanged_value: 'a-md5' },
        { original_value: 'b-md5', refanged_value: 'b-md5' },
      ],
    },
    {
      label: 'URLs',
      items: [
        { original_value: '', refanged_value: '' },
      ],
    },
    {
      label: 'SHA256',
      items: [
        { original_value: 'sha256-a', refanged_value: 'sha256-a' },
      ],
    },
  ]

  const payload = buildHandlingCopyPayload(
    groups,
    INDICATOR_DISPLAY_MODE.REFANGED,
    INDICATOR_WORKFLOW_MODE.DEFENDER,
    'handledByUs',
  )

  assert.equal(payload, 'MD5 (2):\n\na-md5\nb-md5\n\nSHA256 (1):\n\nsha256-a')
  assert.equal(payload.includes('MD5 (2):\n\na-md5'), true)
  assert.equal(payload.includes('b-md5\n\nSHA256 (1):'), true)
  assert.equal(payload.endsWith('\n'), false)
})

test('toast messages use required copy success and failure phrasing', () => {
  assert.equal(getHandlingCopySuccessMessage(280, 'Handled by Us'), 'Copied 280 indicators for Handled by Us.')
  assert.equal(getGroupCopySuccessMessage('Domains', 165), 'Copied 165 Domains.')
  assert.equal(INDICATOR_COPY_ERROR_MESSAGE, 'Unable to copy indicators. Please try again.')
})

test('ignored items are excluded from grouped copy output and valid ordering is preserved', () => {
  const detected = getDetectedIndicators([
    {
      original_value: 'ignore me',
      refanged_value: 'ignore me',
      indicator_type: null,
      valid: false,
      reason: 'unsupported_indicator',
    },
    {
      original_value: 'a[.]com',
      refanged_value: 'a.com',
      indicator_type: 'DomainName',
      valid: true,
    },
    {
      original_value: 'b[.]com',
      refanged_value: 'b.com',
      indicator_type: 'DomainName',
      valid: true,
    },
  ])

  const grouped = groupDetectedIndicatorsByType(detected)
  assert.equal(grouped.length, 1)
  assert.equal(
    buildHandlingCopyPayload(grouped, INDICATOR_DISPLAY_MODE.REFANGED, INDICATOR_WORKFLOW_MODE.CROWDSTRIKE, 'customerAction'),
    'Domains (2):\n\na.com\nb.com',
  )
})
