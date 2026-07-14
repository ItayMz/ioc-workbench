import assert from 'node:assert/strict'
import test from 'node:test'
import * as XLSX from 'xlsx'

import { uploadFiles } from './iocApi.js'

function makeFile(name, content, buffer = null) {
  return {
    name,
    async text() {
      return content
    },
    async arrayBuffer() {
      if (buffer == null) {
        throw new Error('arrayBuffer not available')
      }
      return buffer
    },
  }
}

function makeXlsxBuffer(rowsBySheet) {
  const workbook = XLSX.utils.book_new()
  for (const [sheetName, rows] of rowsBySheet) {
    const worksheet = XLSX.utils.aoa_to_sheet(rows)
    XLSX.utils.book_append_sheet(workbook, worksheet, sheetName)
  }

  return XLSX.write(workbook, { type: 'array', bookType: 'xlsx' })
}

test('two CSV files with different event_info values do not force one campaign override in request payload', async () => {
  let capturedBody = null

  global.fetch = async (_url, options) => {
    capturedBody = JSON.parse(options.body)
    return {
      ok: true,
      async json() {
        return {
          indicators: [],
          valid_count: 0,
          summary: { valid: 0 },
        }
      },
    }
  }

  const first = 'type,value,event_info\nurl,https://first.example,Campaign A'
  const second = 'type,value,event_info\ndomain,second.example,Campaign B'

  const result = await uploadFiles(
    [makeFile('a.csv', first), makeFile('b.csv', second)],
    90,
    null,
  )

  assert.equal(capturedBody.campaignName, null)
  assert.equal(result.requestPayload.campaignName, null)
  assert.equal(result.summary.detectedCampaignName, 'Campaign A')
  assert.equal(result.summary.warning.includes('Multiple campaign names'), true)

  const metadataCampaigns = result.requestPayload.iocMetadata.map((row) => row.campaignName)
  assert.deepEqual(metadataCampaigns, ['Campaign A', 'Campaign B'])
})

test('one CSV with multiple event_info values keeps per-row campaign metadata and no implicit override', async () => {
  let capturedBody = null

  global.fetch = async (_url, options) => {
    capturedBody = JSON.parse(options.body)
    return {
      ok: true,
      async json() {
        return {
          indicators: [],
          valid_count: 0,
          summary: { valid: 0 },
        }
      },
    }
  }

  const csv = [
    'type,value,event_info',
    'url,https://alpha.example,Campaign A',
    'domain,beta.example,Campaign B',
  ].join('\n')

  const result = await uploadFiles([makeFile('mixed.csv', csv)], 90, null)

  assert.equal(capturedBody.campaignName, null)
  assert.equal(result.requestPayload.campaignName, null)
  assert.deepEqual(
    result.requestPayload.iocMetadata.map((row) => row.campaignName),
    ['Campaign A', 'Campaign B'],
  )
})

test('manual campaign name still overrides all rows in request payload', async () => {
  let capturedBody = null

  global.fetch = async (_url, options) => {
    capturedBody = JSON.parse(options.body)
    return {
      ok: true,
      async json() {
        return {
          indicators: [],
          valid_count: 0,
          summary: { valid: 0 },
        }
      },
    }
  }

  const csv = [
    'type,value,event_info',
    'url,https://alpha.example,Campaign A',
    'domain,beta.example,Campaign B',
  ].join('\n')

  const result = await uploadFiles([makeFile('mixed.csv', csv)], 90, 'Manual Campaign')

  assert.equal(capturedBody.campaignName, 'Manual Campaign')
  assert.equal(result.requestPayload.campaignName, 'Manual Campaign')
})

test('upload request payload carries selected defaultCategory', async () => {
  let capturedBody = null

  global.fetch = async (_url, options) => {
    capturedBody = JSON.parse(options.body)
    return {
      ok: true,
      async json() {
        return {
          indicators: [],
          valid_count: 0,
          summary: { valid: 0 },
        }
      },
    }
  }

  const csv = 'type,value,event_info\nurl,https://alpha.example,Campaign A'
  const result = await uploadFiles([makeFile('single.csv', csv)], 90, null, 'Ransomware')

  assert.equal(capturedBody.defaultCategory, 'Ransomware')
  assert.equal(result.requestPayload.defaultCategory, 'Ransomware')
})

test('mixed CSV and XLSX upload sends combined metadata and detected campaign', async () => {
  let capturedBody = null

  global.fetch = async (_url, options) => {
    capturedBody = JSON.parse(options.body)
    return {
      ok: true,
      async json() {
        return {
          indicators: [],
          valid_count: 0,
          summary: { valid: 0 },
        }
      },
    }
  }

  const csv = 'value,event_info,category\nhttps://from-csv.example,Campaign A,Execution'
  const xlsxBuffer = makeXlsxBuffer([
    ['Intel', [
      ['value', 'event_info', 'category'],
      ['8.8.8.8', 'Campaign A', 'C2'],
    ]],
  ])

  const result = await uploadFiles(
    [makeFile('first.csv', csv), makeFile('second.xlsx', '', xlsxBuffer)],
    90,
    null,
  )

  assert.equal(result.summary.detectedCampaignName, 'Campaign A')
  assert.equal(capturedBody.raw_text, 'https://from-csv.example\n8.8.8.8')
  assert.deepEqual(
    capturedBody.iocMetadata.map((row) => ({ value: row.value, campaignName: row.campaignName, category: row.category })),
    [
      { value: 'https://from-csv.example', campaignName: 'Campaign A', category: 'Execution' },
      { value: '8.8.8.8', campaignName: 'Campaign A', category: 'CommandAndControl' },
    ],
  )
})
