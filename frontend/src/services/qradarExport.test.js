import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildQradarCsv,
  buildQradarExportFilename,
  exportQradarCsv,
  getQradarEligibleCount,
  getQradarIpv4Values,
} from './qradarExport.js'

function indicator(indicatorType, refangedValue, valid = true, originalValue = null) {
  return {
    indicator_type: indicatorType,
    refanged_value: refangedValue,
    original_value: originalValue ?? refangedValue,
    valid,
  }
}

function withDownloadMocks(runAssertions) {
  const originalBlob = globalThis.Blob
  const originalUrl = globalThis.URL
  const originalDocument = globalThis.document

  let capturedParts = null
  let capturedType = null

  class MockBlob {
    constructor(parts, options) {
      capturedParts = parts
      capturedType = options?.type
    }
  }

  const anchor = {
    href: '',
    download: '',
    clickCalled: false,
    click() {
      this.clickCalled = true
    },
  }

  globalThis.Blob = MockBlob
  globalThis.URL = {
    createObjectURL() {
      return 'blob:mock-url'
    },
    revokeObjectURL() {},
  }
  globalThis.document = {
    createElement(tagName) {
      assert.equal(tagName, 'a')
      return anchor
    },
    body: {
      appendChild(node) {
        assert.equal(node, anchor)
      },
      removeChild(node) {
        assert.equal(node, anchor)
      },
    },
  }

  try {
    runAssertions(() => ({
      payload: String(capturedParts?.[0] ?? ''),
      mimeType: capturedType,
      clicked: anchor.clickCalled,
    }))
  } finally {
    globalThis.Blob = originalBlob
    globalThis.URL = originalUrl
    globalThis.document = originalDocument
  }
}

test('QRadar export includes only IPv4 values and excludes all other IOC types', () => {
  const values = getQradarIpv4Values([
    indicator('IpAddress', '1.1.1.1'),
    indicator('IpAddress', '2001:db8::1'),
    indicator('FileMd5', 'a'.repeat(32)),
    indicator('FileSha1', 'b'.repeat(40)),
    indicator('FileSha256', 'c'.repeat(64)),
    indicator('DomainName', 'evil.com'),
    indicator('Url', 'https://evil.com'),
    indicator('SenderEmailAddress', 'user@test.com'),
    indicator('Ipv4', '8.8.8.8'),
  ])

  assert.deepEqual(values, ['1.1.1.1', '8.8.8.8'])
})

test('QRadar CSV has no header and contains one IPv4 per line', () => {
  const exportData = buildQradarCsv([
    indicator('IpAddress', '1.1.1.1'),
    indicator('IpAddress', '8.8.8.8'),
  ])

  assert.equal(exportData.csv, '1.1.1.1\n8.8.8.8')
})

test('QRadar export deduplicates values and preserves first-detected ordering', () => {
  const values = getQradarIpv4Values([
    indicator('IpAddress', '8.8.8.8'),
    indicator('IpAddress', '1.1.1.1'),
    indicator('IpAddress', '8.8.8.8'),
    indicator('IpAddress', '1.1.1.1'),
    indicator('IpAddress', '9.9.9.9'),
  ])

  assert.deepEqual(values, ['8.8.8.8', '1.1.1.1', '9.9.9.9'])
})

test('QRadar filename uses campaign name and supports fallback', () => {
  assert.equal(buildQradarExportFilename('Q3 Campaign'), 'Q3-Campaign-qradar-ips.csv')
  assert.equal(buildQradarExportFilename(''), 'qradar-ips.csv')
})

test('QRadar eligible count is zero when no valid IPv4 indicators exist', () => {
  const count = getQradarEligibleCount([
    indicator('DomainName', 'evil.com'),
    indicator('IpAddress', '2001:db8::1'),
    indicator('FileMd5', 'a'.repeat(32)),
  ])

  assert.equal(count, 0)
  assert.equal(buildQradarCsv([
    indicator('DomainName', 'evil.com'),
    indicator('IpAddress', '2001:db8::1'),
  ]), null)
})

test('QRadar export download stays BOM-free so the first IP value is unchanged', () => {
  withDownloadMocks((getResult) => {
    const exported = exportQradarCsv([
      indicator('IpAddress', '1.1.1.1'),
      indicator('IpAddress', '8.8.8.8'),
    ], { campaignName: 'Q3 Campaign' })

    const result = getResult()
    assert.equal(exported.filename, 'Q3-Campaign-qradar-ips.csv')
    assert.equal(exported.count, 2)
    assert.equal(result.mimeType, 'text/csv;charset=utf-8')
    assert.equal(result.clicked, true)
    assert.equal(result.payload.startsWith('\uFEFF'), false)
    assert.equal(result.payload, '1.1.1.1\n8.8.8.8')
  })
})
