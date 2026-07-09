import assert from 'node:assert/strict'
import test from 'node:test'

import { parseUploadedFiles, resolveCampaignName } from './uploadParser.js'

function makeFile(name, content) {
  return {
    name,
    async text() {
      return content
    },
  }
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
    /Unsupported file type\(s\).*\.csv or \.txt files/,
  )
})
