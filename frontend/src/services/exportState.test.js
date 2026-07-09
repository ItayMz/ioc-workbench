import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_DEFENDER_CATEGORY } from './defenderCategories.js'
import {
  getInitialRawText,
  NO_VALID_IOCS_EXPORT_MESSAGE,
  resolveExportRequest,
} from './exportState.js'

test('initial app state cannot export', () => {
  const result = resolveExportRequest({
    lastSuccessfulParsePayload: null,
    lastSuccessfulParseResult: null,
  })

  assert.equal(result.canExport, false)
  assert.equal(result.payload, null)
  assert.equal(result.error, NO_VALID_IOCS_EXPORT_MESSAGE)
})

test('empty parse result cannot export', () => {
  const result = resolveExportRequest({
    lastSuccessfulParsePayload: {
      rawText: '   ',
      iocMetadata: null,
      lookbackDays: 90,
    },
    lastSuccessfulParseResult: {
      valid_count: 0,
    },
  })

  assert.equal(result.canExport, false)
  assert.equal(result.payload, null)
  assert.equal(result.error, NO_VALID_IOCS_EXPORT_MESSAGE)
})

test('zero valid IOCs cannot export', () => {
  const result = resolveExportRequest({
    lastSuccessfulParsePayload: {
      rawText: 'not-an-ioc',
      iocMetadata: null,
      lookbackDays: 90,
    },
    lastSuccessfulParseResult: {
      valid_count: 0,
    },
  })

  assert.equal(result.canExport, false)
  assert.equal(result.payload, null)
  assert.equal(result.error, NO_VALID_IOCS_EXPORT_MESSAGE)
})

test('valid parsed result can export', () => {
  const payload = {
    rawText: 'https://example.com\nevil.com',
    campaignName: 'Storm-123',
    iocMetadata: [
      {
        value: 'https://example.com',
        campaignName: 'Storm-123',
        category: 'CommandAndControl',
        sourceFile: 'upload.csv',
      },
    ],
    lookbackDays: 90,
  }

  const result = resolveExportRequest({
    lastSuccessfulParsePayload: payload,
    lastSuccessfulParseResult: {
      valid_count: 2,
    },
  })

  assert.equal(result.canExport, true)
  assert.equal(result.error, null)
  assert.deepEqual(result.payload, payload)
})

test('Clear disables export again', () => {
  const exportEnabled = resolveExportRequest({
    lastSuccessfulParsePayload: {
      rawText: 'https://example.com',
      iocMetadata: null,
      lookbackDays: 90,
    },
    lastSuccessfulParseResult: {
      valid_count: 1,
    },
  })

  const afterClear = resolveExportRequest({
    lastSuccessfulParsePayload: null,
    lastSuccessfulParseResult: null,
  })

  assert.equal(exportEnabled.canExport, true)
  assert.equal(afterClear.canExport, false)
  assert.equal(afterClear.error, NO_VALID_IOCS_EXPORT_MESSAGE)
})

test('initial textarea is empty', () => {
  assert.equal(getInitialRawText(), '')
})

test('clear default category target is Malware', () => {
  assert.equal(DEFAULT_DEFENDER_CATEGORY, 'Malware')
})
