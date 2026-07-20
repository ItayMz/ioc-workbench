import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import {
  buildDefenderCsv,
  compareDefenderCsvOutputs,
  DEFENDER_CSV_FILENAME,
  downloadDefenderCsv,
} from './defenderCsv.js'

const fixtures = JSON.parse(
  readFileSync(new URL('../../test-fixtures/defender-csv/golden-fixtures.json', import.meta.url), 'utf8'),
)

function indicator(originalValue, refangedValue, indicatorType, action, severity = 'High', generateAlert = true, valid = true) {
  return {
    original_value: originalValue,
    refanged_value: refangedValue,
    indicator_type: indicatorType,
    action,
    severity,
    generate_alert: generateAlert,
    valid,
  }
}

const INDICATORS_BY_FIXTURE_NAME = {
  'all-supported-types-and-sender-exclusion': [
    indicator('hxxps://evil[.]example/path?x=1&y=2', 'https://evil.example/path?x=1&y=2', 'Url', 'Block'),
    indicator('evil.com', 'evil.com', 'DomainName', 'Block'),
    indicator('8.8.8.8', '8.8.8.8', 'IpAddress', 'Block'),
    indicator('d94873ad85946c78543fce6eb38cee78', 'd94873ad85946c78543fce6eb38cee78', 'FileMd5', 'BlockAndRemediate'),
    indicator('1d0f8dd934cd975e0b70e1c2d8b1c5b2d438b25d', '1d0f8dd934cd975e0b70e1c2d8b1c5b2d438b25d', 'FileSha1', 'BlockAndRemediate'),
    indicator('a02f124c5ce4180bd130a62ee03262f399c33491de3aed36e0b15155ae4926c0', 'a02f124c5ce4180bd130a62ee03262f399c33491de3aed36e0b15155ae4926c0', 'FileSha256', 'BlockAndRemediate'),
    indicator('user@test.com', 'user@test.com', 'SenderEmailAddress', null, null, null),
  ],
  'detected-campaign-and-source-file-fallback': [
    indicator('https://first.example/path', 'https://first.example/path', 'Url', 'Block'),
    indicator('second.example', 'second.example', 'DomainName', 'Block'),
    indicator('10.10.10.10', '10.10.10.10', 'IpAddress', 'Block'),
  ],
  'category-normalization-and-defaults': [
    indicator('https://alias.example', 'https://alias.example', 'Url', 'Block'),
    indicator('198.51.100.7', '198.51.100.7', 'IpAddress', 'Block'),
    indicator('abc123def4567890abc123def4567890', 'abc123def4567890abc123def4567890', 'FileMd5', 'BlockAndRemediate'),
    indicator('example.org', 'example.org', 'DomainName', 'Block'),
  ],
  'duplicate-indicators-preserved': [
    indicator('8.8.8.8', '8.8.8.8', 'IpAddress', 'Block'),
    indicator('8.8.8.8', '8.8.8.8', 'IpAddress', 'Block'),
    indicator('dup.example', 'dup.example', 'DomainName', 'Block'),
    indicator('dup.example', 'dup.example', 'DomainName', 'Block'),
  ],
  'escaping-unicode-and-newlines': [
    indicator('https://example.com/path?query=a,b&quote="x"', 'https://example.com/path?query=a,b&quote="x"', 'Url', 'Block'),
    indicator('\u05e9\u05dc\u05d5\u05dd.example', '\u05e9\u05dc\u05d5\u05dd.example', 'DomainName', 'Block'),
    indicator('line1\nline2', 'line1\nline2', 'DomainName', 'Block'),
  ],
}

function getFixtureInput(fixture) {
  return {
    ...fixture.input,
    indicators: INDICATORS_BY_FIXTURE_NAME[fixture.name],
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
      download: anchor.download,
    }))
  } finally {
    globalThis.Blob = originalBlob
    globalThis.URL = originalUrl
    globalThis.document = originalDocument
  }
}

function parseCsvRows(csvText) {
  const rows = []
  let row = []
  let field = ''
  let inQuotes = false

  for (let index = 0; index < csvText.length; index += 1) {
    const char = csvText[index]

    if (char === '"') {
      const nextChar = csvText[index + 1]
      if (inQuotes && nextChar === '"') {
        field += '"'
        index += 1
      } else {
        inQuotes = !inQuotes
      }
      continue
    }

    if (!inQuotes && char === ',') {
      row.push(field)
      field = ''
      continue
    }

    if (!inQuotes && (char === '\n' || char === '\r')) {
      if (char === '\r' && csvText[index + 1] === '\n') {
        index += 1
      }
      row.push(field)
      rows.push(row)
      row = []
      field = ''
      continue
    }

    field += char
  }

  row.push(field)
  if (row.length > 1 || row[0].trim()) {
    rows.push(row)
  }

  return rows
}

function stripBom(text) {
  return text.startsWith('\ufeff') ? text.slice(1) : text
}

test('buildDefenderCsv matches the backend golden fixtures exactly', () => {
  for (const fixture of fixtures.cases) {
    const actual = buildDefenderCsv(getFixtureInput(fixture))
    const diff = compareDefenderCsvOutputs(fixture.expectedDownloadTextWithBom, actual)

    assert.equal(
      actual,
      fixture.expectedDownloadTextWithBom,
      `Fixture ${fixture.name} diverged at byte ${diff.firstDifferentByte ?? 'n/a'}`,
    )
    assert.equal(diff.equal, true)
  }
})

test('header order and blank template columns remain unchanged', () => {
  const fixture = fixtures.cases[0]
  const rows = parseCsvRows(stripBom(buildDefenderCsv(getFixtureInput(fixture))))
  const header = rows[0]

  assert.deepEqual(header, [
    'IndicatorType',
    'IndicatorValue',
    'ExpirationTime',
    'Action',
    'Severity',
    'Title',
    'Description',
    'RecommendedActions',
    'RbacGroups',
    'Category',
    'MitreTechniques',
    'GenerateAlert',
  ])

  for (const row of rows.slice(1)) {
    assert.equal(row.length, 12)
    assert.equal(row[2], '')
    assert.equal(row[7], '')
    assert.equal(row[8], '')
    assert.equal(row[10], '')
  }
})

test('sender emails are excluded and duplicate rows are preserved', () => {
  const senderFixture = fixtures.cases[0]
  const senderRows = parseCsvRows(stripBom(buildDefenderCsv(getFixtureInput(senderFixture)))).slice(1)
  assert.equal(senderRows.some((row) => row[0] === 'SenderEmailAddress'), false)
  assert.equal(senderRows.length, 6)

  const duplicateFixture = fixtures.cases[3]
  const duplicateRows = parseCsvRows(stripBom(buildDefenderCsv(getFixtureInput(duplicateFixture)))).slice(1)
  assert.equal(duplicateRows.length, 4)
  assert.deepEqual(duplicateRows.map((row) => row[1]), ['8.8.8.8', '8.8.8.8', 'dup.example', 'dup.example'])
})

test('campaign fallback and category normalization remain correct', () => {
  const fallbackFixture = fixtures.cases[1]
  const fallbackRows = parseCsvRows(stripBom(buildDefenderCsv(getFixtureInput(fallbackFixture)))).slice(1)

  assert.equal(fallbackRows[2][5], 'Detected Alpha IOC')
  assert.equal(fallbackRows[2][6], 'Indicators associated with Detected Alpha.')

  const categoryFixture = fixtures.cases[2]
  const categoryRows = parseCsvRows(stripBom(buildDefenderCsv(getFixtureInput(categoryFixture)))).slice(1)

  assert.deepEqual(categoryRows.map((row) => row[9]), [
    'CommandAndControl',
    'CommandAndControl',
    'Ransomware',
    'Malware',
  ])
})

test('CSV escaping preserves commas quotes newlines and Unicode/Hebrew', () => {
  const fixture = fixtures.cases[4]
  const actual = buildDefenderCsv(getFixtureInput(fixture))
  const rows = parseCsvRows(stripBom(actual))

  assert.equal(actual.startsWith('\ufeffIndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert\r\n'), true)
  assert.equal(actual.includes('Manual, ""הקמפיין""'), true)
  assert.equal(actual.includes('https://example.com/path?query=a,b&quote=""x""'), true)
  assert.equal(actual.includes('line1\nline2'), true)
  assert.equal(rows[1][1], 'https://example.com/path?query=a,b&quote="x"')
  assert.equal(rows[2][1], 'שלום.example')
  assert.equal(rows[3][1], 'line1\nline2')
})

test('downloadDefenderCsv uses the fixed filename and keeps the BOM exactly once', () => {
  withDownloadMocks((getResult) => {
    const exported = downloadDefenderCsv(getFixtureInput(fixtures.cases[0]))
    const result = getResult()

    assert.equal(exported.filename, DEFENDER_CSV_FILENAME)
    assert.equal(result.download, DEFENDER_CSV_FILENAME)
    assert.equal(result.mimeType, 'text/csv;charset=utf-8')
    assert.equal(result.clicked, true)
    assert.equal(result.payload, fixtures.cases[0].expectedDownloadTextWithBom)
    assert.equal(result.payload.startsWith('\ufeff'), true)
    assert.equal(result.payload.startsWith('\ufeff\ufeff'), false)
  })
})
