import assert from 'node:assert/strict'
import test from 'node:test'

import { buildDefenderExportNotice } from './defenderExportNotice.js'
import { WORKFLOW_MODE } from './workflowMode.js'

function indicator(indicatorType, value, valid = true) {
  return {
    indicator_type: indicatorType,
    refanged_value: value,
    original_value: value,
    valid,
  }
}

test('no Defender export note is shown when no sender email addresses are detected', () => {
  const notice = buildDefenderExportNotice({
    workflowMode: WORKFLOW_MODE.DEFENDER,
    indicators: [indicator('ipv4', '192.0.2.10')],
  })

  assert.equal(notice, null)
})

test('singular wording is used for one sender email address', () => {
  const notice = buildDefenderExportNotice({
    workflowMode: WORKFLOW_MODE.DEFENDER,
    indicators: [indicator('senderemailaddress', 'user@example.com'), indicator('ipv4', '192.0.2.10')],
  })

  assert.equal(notice?.message, '1 sender email indicator was detected. Use the Sender Email KQL sweep query for investigation; sender email blocking is not included in the Defender CSV export.')
  assert.equal(notice?.countsText, 'Detected indicators: 2 · Exportable to Defender: 1 · Excluded email addresses: 1')
})

test('plural wording is used for multiple sender email addresses', () => {
  const notice = buildDefenderExportNotice({
    workflowMode: WORKFLOW_MODE.DEFENDER,
    indicators: [
      indicator('senderemailaddress', 'user@example.com'),
      indicator('senderemailaddress', 'analyst@example.com'),
      indicator('ipv4', '192.0.2.10'),
    ],
  })

  assert.equal(notice?.message, '2 sender email indicators were detected. Use the Sender Email KQL sweep query for investigation; sender email blocking is not included in the Defender CSV export.')
  assert.equal(notice?.countsText, 'Detected indicators: 3 · Exportable to Defender: 1 · Excluded email addresses: 2')
})

test('Defender export note does not render in CrowdStrike workflow', () => {
  const notice = buildDefenderExportNotice({
    workflowMode: WORKFLOW_MODE.CROWDSTRIKE,
    indicators: [indicator('senderemailaddress', 'user@example.com')],
  })

  assert.equal(notice, null)
})