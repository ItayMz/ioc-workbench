import assert from 'node:assert/strict'
import test from 'node:test'

import { mergeAccumulatedSubmission } from './accumulation.js'

function buildResult(indicators) {
  return { indicators }
}

function ioc(original, refanged, type) {
  return {
    original_value: original,
    refanged_value: refanged,
    indicator_type: type,
    valid: true,
  }
}

test('file then file accumulation preserves first result and adds unique new IOCs', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8\nevil.com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: '8.8.8.8', campaignName: 'Campaign A', category: 'Execution', sourceFile: 'a.csv' },
        { value: 'evil.com', campaignName: 'Campaign A', category: 'Discovery', sourceFile: 'a.csv' },
      ],
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
    incomingPayload: {
      rawText: `${'a'.repeat(64)}\n1.1.1.1`,
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: `${'a'.repeat(64)}`, campaignName: 'Campaign B', category: 'Malware', sourceFile: 'b.xlsx' },
        { value: '1.1.1.1', campaignName: 'Campaign B', category: 'CommandAndControl', sourceFile: 'b.xlsx' },
      ],
    },
    incomingResult: buildResult([
      ioc(`${'a'.repeat(64)}`, `${'a'.repeat(64)}`, 'FileSha256'),
      ioc('1.1.1.1', '1.1.1.1', 'IpAddress'),
    ]),
  })

  assert.equal(merged.rawText, `8.8.8.8\nevil.com\n${'a'.repeat(64)}\n1.1.1.1`)
  assert.equal(merged.iocMetadata.length, 4)
})

test('free text then free text accumulates globally deduped IOCs', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8\nevil.com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
    incomingPayload: {
      rawText: '1.1.1.1\nexample.org',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    incomingResult: buildResult([
      ioc('1.1.1.1', '1.1.1.1', 'IpAddress'),
      ioc('example.org', 'example.org', 'DomainName'),
    ]),
  })

  assert.equal(merged.rawText, '8.8.8.8\nevil.com\n1.1.1.1\nexample.org')
})

test('file then free text retains file indicators and appends text indicators', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8\nevil.com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: '8.8.8.8', campaignName: 'File Campaign', category: 'Execution', sourceFile: 'source.csv' },
        { value: 'evil.com', campaignName: 'File Campaign', category: 'Discovery', sourceFile: 'source.csv' },
      ],
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
    incomingPayload: {
      rawText: '1.1.1.1\nexample.org',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    incomingResult: buildResult([
      ioc('1.1.1.1', '1.1.1.1', 'IpAddress'),
      ioc('example.org', 'example.org', 'DomainName'),
    ]),
  })

  assert.equal(merged.rawText, '8.8.8.8\nevil.com\n1.1.1.1\nexample.org')
  assert.equal(merged.iocMetadata.length, 2)
})

test('free text then file retains text indicators and appends file indicators with metadata', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8\nevil.com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
    incomingPayload: {
      rawText: `${'a'.repeat(64)}\n1.1.1.1`,
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: `${'a'.repeat(64)}`, campaignName: 'Upload Campaign', category: 'Execution', sourceFile: 'new.xlsx' },
        { value: '1.1.1.1', campaignName: 'Upload Campaign', category: 'CommandAndControl', sourceFile: 'new.xlsx' },
      ],
    },
    incomingResult: buildResult([
      ioc(`${'a'.repeat(64)}`, `${'a'.repeat(64)}`, 'FileSha256'),
      ioc('1.1.1.1', '1.1.1.1', 'IpAddress'),
    ]),
  })

  assert.equal(merged.rawText, `8.8.8.8\nevil.com\n${'a'.repeat(64)}\n1.1.1.1`)
  assert.equal(merged.iocMetadata.length, 2)
})

test('global deduplication handles refanged duplicates across submissions', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8\nevil[.]com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil[.]com', 'evil.com', 'DomainName'),
    ]),
    incomingPayload: {
      rawText: '8.8.8.8\nevil.com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    incomingResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
  })

  assert.equal(merged.rawText, '8.8.8.8\nevil[.]com')
})

test('sender emails are preserved and deduplicated during accumulation merge', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: 'user@test.com\n8.8.8.8',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    currentResult: buildResult([
      ioc('user@test.com', 'user@test.com', 'SenderEmailAddress'),
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
    ]),
    incomingPayload: {
      rawText: 'analyst@test.com\nevil.com',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    incomingResult: buildResult([
      ioc('USER@TEST.COM', 'USER@TEST.COM', 'SenderEmailAddress'),
      ioc('analyst@test.com', 'analyst@test.com', 'SenderEmailAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
  })

  assert.equal(merged.rawText, 'user@test.com\n8.8.8.8\nanalyst@test.com\nevil.com')
})

test('duplicate IOC metadata keeps first accepted occurrence', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: '8.8.8.8', campaignName: 'First Campaign', category: 'Execution', sourceFile: 'first.csv' },
      ],
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
    ]),
    incomingPayload: {
      rawText: '8.8.8.8',
      lookbackDays: 90,
      campaignName: null,
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: '8.8.8.8', campaignName: 'Second Campaign', category: 'Discovery', sourceFile: 'second.xlsx' },
      ],
    },
    incomingResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
    ]),
  })

  assert.equal(merged.iocMetadata.length, 1)
  assert.deepEqual(merged.iocMetadata[0], {
    value: '8.8.8.8',
    campaignName: 'First Campaign',
    category: 'Execution',
    sourceFile: 'first.csv',
  })
})

test('incoming sender-email-only batch is accumulated like other valid indicators', () => {
  const merged = mergeAccumulatedSubmission({
    currentPayload: {
      rawText: '8.8.8.8\nevil.com',
      lookbackDays: 90,
      campaignName: 'Existing Campaign',
      defaultCategory: 'Malware',
      iocMetadata: [
        { value: '8.8.8.8', campaignName: 'Existing Campaign', category: 'Execution', sourceFile: 'valid.csv' },
      ],
    },
    currentResult: buildResult([
      ioc('8.8.8.8', '8.8.8.8', 'IpAddress'),
      ioc('evil.com', 'evil.com', 'DomainName'),
    ]),
    incomingPayload: {
      rawText: 'user@test.com\nanalyst@test.com',
      lookbackDays: 90,
      campaignName: 'Existing Campaign',
      defaultCategory: 'Malware',
      iocMetadata: null,
    },
    incomingResult: buildResult([
      ioc('user@test.com', 'user@test.com', 'SenderEmailAddress'),
      ioc('analyst@test.com', 'analyst@test.com', 'SenderEmailAddress'),
    ]),
  })

  assert.equal(merged.rawText, '8.8.8.8\nevil.com\nuser@test.com\nanalyst@test.com')
  assert.equal(merged.iocMetadata.length, 1)
})
