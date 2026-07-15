import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildSenderEmailCopyPayload,
  getDetectedSenderEmailAddresses,
} from './senderEmailWorkflow.js'

test('single sender email is normalized to lowercase', () => {
  const senderEmails = getDetectedSenderEmailAddresses([
    {
      indicator_type: 'SenderEmailAddress',
      refanged_value: 'User@Test.COM',
      valid: true,
    },
  ])

  assert.deepEqual(senderEmails, ['user@test.com'])
})

test('multiple sender emails are deduplicated and lowercased', () => {
  const senderEmails = getDetectedSenderEmailAddresses([
    { indicator_type: 'SenderEmailAddress', refanged_value: 'User@Test.COM', valid: true },
    { indicator_type: 'SenderEmailAddress', refanged_value: 'user@test.com', valid: true },
    { indicator_type: 'SenderEmailAddress', refanged_value: 'Analyst@Test.com', valid: true },
  ])

  assert.deepEqual(senderEmails, ['user@test.com', 'analyst@test.com'])
})

test('Copy Emails payload is newline separated', () => {
  const payload = buildSenderEmailCopyPayload(['one@example.com', 'two@example.com'])

  assert.equal(payload, 'one@example.com\ntwo@example.com')
})

test('invalid sender indicator entries are ignored', () => {
  const senderEmails = getDetectedSenderEmailAddresses([
    { indicator_type: 'SenderEmailAddress', refanged_value: 'user@test.com', valid: false },
    { indicator_type: 'IpAddress', refanged_value: '1.1.1.1', valid: true },
  ])

  assert.deepEqual(senderEmails, [])
})
