import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildCrowdStrikeAdvancedEventSearchQuery,
  CROWDSTRIKE_ADVANCED_EVENT_SEARCH_TYPE_ORDER,
} from './crowdstrikeQueryBuilder.js'

function indicator(indicatorType, refangedValue, valid = true, originalValue = null) {
  return {
    indicator_type: indicatorType,
    refanged_value: refangedValue,
    original_value: originalValue ?? refangedValue,
    valid,
  }
}

test('single valid indicator generates a CrowdStrike query', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('IpAddress', '10.0.0.1'),
  ])

  assert.equal(result.query, '10.0.0.1')
  assert.equal(result.totalUniqueIocCount, 1)
  assert.equal(result.uniqueTypeCount, 1)
})

test('multiple indicators are joined with the exact operator or', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('IpAddress', '10.0.0.1'),
    indicator('DomainName', 'evil.com'),
  ])

  assert.equal(result.query, '10.0.0.1 or evil.com')
})

test('query includes every supported parsed IOC type', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('IpAddress', '10.0.0.1'),
    indicator('IpAddress', '2001:db8::1'),
    indicator('FileMd5', '098f6bcd4621d373cade4e832627b4f6'),
    indicator('FileSha1', 'a9993e364706816aba3e25717850c26c9cd0d89d'),
    indicator('FileSha256', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'),
    indicator('DomainName', 'google.com'),
    indicator('Url', 'https://evil.com/login?id=1'),
    indicator('SenderEmailAddress', 'attacker@example.com'),
  ])

  assert.equal(
    result.query,
    '10.0.0.1 or 2001:db8::1 or 098f6bcd4621d373cade4e832627b4f6 or a9993e364706816aba3e25717850c26c9cd0d89d or 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 or google.com or "https://evil.com/login?id=1" or "attacker@example.com"',
  )
})

test('indicators are sorted using the required IOC type order', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('SenderEmailAddress', 'user@test.com'),
    indicator('Url', 'https://evil.com'),
    indicator('DomainName', 'evil.com'),
    indicator('FileSha256', '1'.repeat(64)),
    indicator('FileSha1', '2'.repeat(40)),
    indicator('FileMd5', '3'.repeat(32)),
    indicator('IpAddress', '2001:db8::2'),
    indicator('IpAddress', '8.8.8.8'),
  ])

  assert.equal(
    result.query,
    '8.8.8.8 or 2001:db8::2 or 33333333333333333333333333333333 or 2222222222222222222222222222222222222222 or 1111111111111111111111111111111111111111111111111111111111111111 or evil.com or "https://evil.com" or "user@test.com"',
  )
})

test('stable order is preserved within each IOC type group', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('IpAddress', '2.2.2.2'),
    indicator('IpAddress', '1.1.1.1'),
    indicator('DomainName', 'z.com'),
    indicator('DomainName', 'a.com'),
  ])

  assert.equal(result.query, '2.2.2.2 or 1.1.1.1 or z.com or a.com')
})

test('duplicate indicators are removed', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('DomainName', 'evil.com'),
    indicator('DomainName', 'EVIL.COM'),
    indicator('Url', 'https://evil.com'),
    indicator('Url', 'https://evil.com'),
  ])

  assert.equal(result.query, 'evil.com or "https://evil.com"')
  assert.equal(result.totalUniqueIocCount, 2)
})

test('refanged values are used in the query', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('DomainName', 'evil.com', true, 'evil[.]com'),
    indicator('Url', 'https://evil.com/path', true, 'hxxps://evil[.]com/path'),
  ])

  assert.equal(result.query, 'evil.com or "https://evil.com/path"')
})

test('URLs and sender emails are always wrapped in double quotes', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('Url', 'https://evil.com/login?id=1&user=test'),
    indicator('SenderEmailAddress', 'attacker+finance@example.com'),
  ])

  assert.equal(result.query, '"https://evil.com/login?id=1&user=test" or "attacker+finance@example.com"')
})

test('IPv4 IPv6 hashes and domains are not wrapped in quotes', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('IpAddress', '10.0.0.1'),
    indicator('IpAddress', '2001:db8::3'),
    indicator('FileMd5', 'a'.repeat(32)),
    indicator('FileSha1', 'b'.repeat(40)),
    indicator('FileSha256', 'c'.repeat(64)),
    indicator('DomainName', 'evil.com'),
  ])

  assert.equal(result.query.includes('"'), false)
})

test('literal double quotes inside quoted values are escaped safely', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('Url', 'https://example.com/?q="test"'),
    indicator('SenderEmailAddress', 'user"x"@example.com'),
  ])

  assert.equal(result.query, '"https://example.com/?q=\\"test\\"" or "user\\"x\\"@example.com"')
})

test('query output is a single string and metadata reports unique counts', () => {
  const result = buildCrowdStrikeAdvancedEventSearchQuery([
    indicator('IpAddress', '10.0.0.1'),
    indicator('DomainName', 'evil.com'),
    indicator('DomainName', 'evil.com'),
    indicator('Url', 'https://evil.com'),
  ])

  assert.equal(typeof result.query, 'string')
  assert.equal(result.query.includes(' or '), true)
  assert.equal(result.totalUniqueIocCount, 3)
  assert.equal(result.uniqueTypeCount, 3)
})

test('returns null when there are no valid supported indicators', () => {
  assert.equal(buildCrowdStrikeAdvancedEventSearchQuery([]), null)
  assert.equal(
    buildCrowdStrikeAdvancedEventSearchQuery([
      indicator('UnknownType', 'value', true),
      indicator('DomainName', 'evil.com', false),
    ]),
    null,
  )
})

test('exports the exact supported IOC type order contract', () => {
  assert.deepEqual(CROWDSTRIKE_ADVANCED_EVENT_SEARCH_TYPE_ORDER, [
    'ipv4',
    'ipv6',
    'md5',
    'sha1',
    'sha256',
    'domain',
    'url',
    'sender_email',
  ])
})
