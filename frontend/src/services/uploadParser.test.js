import assert from 'node:assert/strict'
import test from 'node:test'
import * as XLSX from 'xlsx'

import { parseUploadedFiles, resolveCampaignName } from './uploadParser.js'

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

test('CSV with value column extracts only IOC values', async () => {
  const csv = [
    'type,value,event_info',
    'url,https://example.com,Campaign A',
    'domain,evil.com,Campaign A',
  ].join('\n')

  const result = await parseUploadedFiles([makeFile('sample.csv', csv)])
  assert.equal(result.rawText, 'https://example.com\nevil.com')
  assert.equal(result.summary.iocsExtracted, 2)
})

test('event_info campaign name is detected', async () => {
  const csv = [
    'type,value,event_info',
    'url,https://example.com,Storm-123',
    'domain,evil.com,Storm-123',
    'ip,8.8.8.8,Other',
  ].join('\n')

  const result = await parseUploadedFiles([makeFile('campaign.csv', csv)])
  assert.equal(result.summary.detectedCampaignName, 'Storm-123')
})

test('CSV category aliases are normalized into Defender categories', async () => {
  const csv = [
    'value,event_info,threat category',
    'https://example.com,Storm-123,C2',
    'evil.com,Storm-123,credential access',
  ].join('\n')

  const result = await parseUploadedFiles([makeFile('categories.csv', csv)])
  assert.equal(result.iocMetadata[0].category, 'CommandAndControl')
  assert.equal(result.iocMetadata[1].category, 'CredentialAccess')
})

test('CSV upload preserves per-row metadata entries', async () => {
  const csv = [
    'value,event_info,category',
    'https://one.com,Campaign One,Execution',
    'two.com,Campaign Two,Discovery',
  ].join('\n')

  const result = await parseUploadedFiles([makeFile('metadata.csv', csv)])
  assert.deepEqual(result.iocMetadata, [
    {
      value: 'https://one.com',
      campaignName: 'Campaign One',
      category: 'Execution',
      sourceFile: 'metadata.csv',
    },
    {
      value: 'two.com',
      campaignName: 'Campaign Two',
      category: 'Discovery',
      sourceFile: 'metadata.csv',
    },
  ])
})

test('manual campaign name overrides detected campaign name', () => {
  const resolved = resolveCampaignName('Manual Name', 'Detected Name')
  assert.equal(resolved, 'Manual Name')
})

test('multiple CSV files combine IOC values', async () => {
  const first = 'type,value,event_info\nurl,https://one.com,First'
  const second = 'type,value,event_info\ndomain,two.com,First'

  const result = await parseUploadedFiles([
    makeFile('first.csv', first),
    makeFile('second.csv', second),
  ])

  assert.equal(result.rawText, 'https://one.com\ntwo.com')
  assert.equal(result.summary.filesUploaded, 2)
})

test('dropping valid CSV and TXT files together uses shared upload pipeline', async () => {
  const csv = 'type,value,event_info\nurl,https://drop.com,Drop Campaign'
  const txt = '8.8.8.8\n'

  const result = await parseUploadedFiles([
    makeFile('dropped.csv', csv),
    makeFile('dropped.txt', txt),
  ])

  assert.equal(result.summary.filesUploaded, 2)
  assert.equal(result.summary.iocsExtracted, 2)
  assert.equal(result.rawText, 'https://drop.com\n8.8.8.8')
  assert.equal(result.summary.detectedCampaignName, 'Drop Campaign')
})

test('TXT upload still works', async () => {
  const txt = 'https://alpha.com\n8.8.8.8\n\n'
  const result = await parseUploadedFiles([makeFile('sample.txt', txt)])

  assert.equal(result.summary.iocsExtracted, 2)
  assert.equal(result.rawText, 'https://alpha.com\n8.8.8.8')
})

test('malformed CSV shows friendly error', async () => {
  const malformed = 'type,value,event_info\nurl,"https://bad.com,Campaign X'

  await assert.rejects(
    () => parseUploadedFiles([makeFile('bad.csv', malformed)]),
    /Malformed CSV file/,
  )
})

test('dropping unsupported files shows friendly error message', async () => {
  await assert.rejects(
    () => parseUploadedFiles([makeFile('bad.json', '{"ioc":"evil.com"}')]),
    /Unsupported file type\(s\).*\.csv, \.txt, or \.xlsx files/,
  )
})

test('XLSX with value/event_info/category matches CSV parsing behavior', async () => {
  const csv = [
    'value,event_info,category',
    'https://example.com,Storm-123,C2',
    'evil.com,Storm-123,credential access',
  ].join('\n')

  const xlsxBuffer = makeXlsxBuffer([
    ['Sheet1', [
      ['value', 'event_info', 'category'],
      ['https://example.com', 'Storm-123', 'C2'],
      ['evil.com', 'Storm-123', 'credential access'],
    ]],
  ])

  const csvResult = await parseUploadedFiles([makeFile('sample.csv', csv)])
  const xlsxResult = await parseUploadedFiles([makeFile('sample.xlsx', '', xlsxBuffer)])

  assert.equal(xlsxResult.rawText, csvResult.rawText)
  assert.equal(xlsxResult.summary.detectedCampaignName, csvResult.summary.detectedCampaignName)
  assert.deepEqual(xlsxResult.iocMetadata, csvResult.iocMetadata.map((row) => ({ ...row, sourceFile: 'sample.xlsx' })))
})

test('mixed CSV and XLSX uploads preserve campaign detection and category mapping', async () => {
  const csv = [
    'value,event_info,category',
    'https://from-csv.example,Campaign A,Execution',
  ].join('\n')
  const xlsxBuffer = makeXlsxBuffer([
    ['Intel', [
      ['value', 'event_info', 'category'],
      ['8.8.8.8', 'Campaign A', 'C2'],
    ]],
  ])

  const result = await parseUploadedFiles([
    makeFile('first.csv', csv),
    makeFile('second.xlsx', '', xlsxBuffer),
  ])

  assert.equal(result.summary.filesUploaded, 2)
  assert.equal(result.summary.detectedCampaignName, 'Campaign A')
  assert.equal(result.rawText, 'https://from-csv.example\n8.8.8.8')
  assert.equal(result.iocMetadata[0].category, 'Execution')
  assert.equal(result.iocMetadata[1].category, 'CommandAndControl')
})

test('reference-style headerless XLSX fallback extracts hashes, urls, ips and ignores labels/email/port notes', async () => {
  const xlsxBuffer = makeXlsxBuffer([
    ['Intel', [
      ['HASH'],
      ['1d865b3a5b803febddaa2a0c07099ceb', 'md5'],
      ['1d0f8dd934cd975e0b70e1c2d8b1c5b2d438b25d', 'sha1'],
      ['a02f124c5ce4180bd130a62ee03262f399c33491de3aed36e0b15155ae4926c0', 'sha256'],
      [''],
      ['URL'],
      ['hxxps://45[.]150[.]109[.]151[.]sslip[.]io:23088/app/js/jquery[.]min[.]js'],
      ['hxxps://194[.]213[.]18[.]133[.]sslip[.]io:23088/app/js/jquery[.]min[.]js'],
      ['hxxps://45[.]150[.]109[.]151[.]sslip[.]io', 'On port 23088'],
      ['hxxps://194[.]213[.]18[.]133[.]sslip[.]io', 'On port 23088'],
      ['hxxp://45[.]86[.]229[.]111/slw', 'On port 8080'],
      [''],
      ['IP'],
      ['45[.]150[.]109[.]151'],
      ['194[.]213[.]18[.]133'],
      ['45[.]86[.]229[.]111'],
      [''],
      ['EMAIL'],
      ['jpcontreras@newfield[.]cl'],
    ]],
  ])

  const result = await parseUploadedFiles([makeFile('reference.xlsx', '', xlsxBuffer)])
  const values = result.rawText.split('\n')

  assert.equal(values.includes('1d865b3a5b803febddaa2a0c07099ceb'), true)
  assert.equal(values.includes('1d0f8dd934cd975e0b70e1c2d8b1c5b2d438b25d'), true)
  assert.equal(values.includes('a02f124c5ce4180bd130a62ee03262f399c33491de3aed36e0b15155ae4926c0'), true)
  assert.equal(values.includes('hxxps://45[.]150[.]109[.]151[.]sslip[.]io:23088/app/js/jquery[.]min[.]js'), true)
  assert.equal(values.includes('45[.]150[.]109[.]151'), true)

  assert.equal(values.includes('HASH'), false)
  assert.equal(values.includes('URL'), false)
  assert.equal(values.includes('IP'), false)
  assert.equal(values.includes('EMAIL'), false)
  assert.equal(values.includes('md5'), false)
  assert.equal(values.includes('sha1'), false)
  assert.equal(values.includes('sha256'), false)
  assert.equal(values.includes('On port 23088'), false)
  assert.equal(values.includes('On port 8080'), false)
  assert.equal(values.some((value) => value.includes('@')), false)

  assert.equal(result.summary.iocsExtracted >= 11, true)
})

test('headerless CSV fallback extracts supported IOC values', async () => {
  const csv = [
    'HASH',
    '1d865b3a5b803febddaa2a0c07099ceb,md5',
    'URL',
    'hxxps://evil[.]example/path,On port 23088',
    'IP',
    '8[.]8[.]8[.]8',
  ].join('\n')

  const result = await parseUploadedFiles([makeFile('headerless.csv', csv)])
  const values = result.rawText.split('\n')

  assert.equal(values.includes('1d865b3a5b803febddaa2a0c07099ceb'), true)
  assert.equal(values.includes('hxxps://evil[.]example/path'), true)
  assert.equal(values.includes('8[.]8[.]8[.]8'), true)
  assert.equal(values.includes('HASH'), false)
  assert.equal(values.includes('On port 23088'), false)
})

test('fallback scanning finds IOCs in non-first columns', async () => {
  const xlsxBuffer = makeXlsxBuffer([
    ['Sheet1', [
      ['', ''],
      ['label', 'hxxps://evil[.]example/path'],
      ['note', '8[.]8[.]8[.]8'],
      ['', ''],
      ['meta', '1d865b3a5b803febddaa2a0c07099ceb'],
    ]],
  ])

  const result = await parseUploadedFiles([makeFile('non-first-column.xlsx', '', xlsxBuffer)])
  const values = result.rawText.split('\n')

  assert.equal(values.includes('hxxps://evil[.]example/path'), true)
  assert.equal(values.includes('8[.]8[.]8[.]8'), true)
  assert.equal(values.includes('1d865b3a5b803febddaa2a0c07099ceb'), true)
})

test('fallback extracts multiple IOCs from one cell', async () => {
  const xlsxBuffer = makeXlsxBuffer([
    ['Sheet1', [
      ['Observed 8.8.8.8 and evil[.]example'],
    ]],
  ])

  const result = await parseUploadedFiles([makeFile('multi-in-cell.xlsx', '', xlsxBuffer)])
  const values = result.rawText.split('\n')

  assert.equal(values.includes('8.8.8.8'), true)
  assert.equal(values.includes('evil[.]example'), true)
})

test('metadata labels and descriptive text do not become IOC candidates', async () => {
  const xlsxBuffer = makeXlsxBuffer([
    ['Sheet1', [
      ['HASH'],
      ['URL'],
      ['IP'],
      ['md5'],
      ['sha1'],
      ['sha256'],
      ['On port 23088'],
      ['Description'],
      ['Suspicious activity'],
    ]],
  ])

  await assert.rejects(
    () => parseUploadedFiles([makeFile('labels-only.xlsx', '', xlsxBuffer)]),
    /No IOC values were extracted from uploaded files/,
  )
})

test('structured value column regression remains unchanged', async () => {
  const csv = [
    'value,event_info,category',
    'https://example.com,Storm-123,C2',
    'evil.com,Storm-123,credential access',
  ].join('\n')

  const result = await parseUploadedFiles([makeFile('value-column.csv', csv)])
  assert.equal(result.rawText, 'https://example.com\nevil.com')
  assert.equal(result.summary.detectedCampaignName, 'Storm-123')
  assert.equal(result.iocMetadata[0].category, 'CommandAndControl')
  assert.equal(result.iocMetadata[1].category, 'CredentialAccess')
})

test('email-only headerless file produces no-supported-IOC behavior', async () => {
  const csv = [
    'EMAIL',
    'user@example[.]com',
  ].join('\n')

  await assert.rejects(
    () => parseUploadedFiles([makeFile('email-only.csv', csv)]),
    /No IOC values were extracted from uploaded files/,
  )
})
