import assert from 'node:assert/strict'
import test from 'node:test'

import {
  DETECTED_EMPTY_MESSAGE,
  getFriendlyIgnoredReason,
  isIgnoredCollapsedByDefault,
  splitDetectedAndIgnored,
  toggleIgnoredExpanded,
} from './indicatorPresentation.js'

test('main table input includes only valid supported indicators', () => {
  const { detected } = splitDetectedAndIgnored([
    {
      original_value: 'https://good.example',
      refanged_value: 'https://good.example',
      indicator_type: 'Url',
      valid: true,
    },
    {
      original_value: 'freeform text',
      refanged_value: 'freeform text',
      indicator_type: null,
      valid: false,
      reason: 'unsupported_indicator',
    },
    {
      original_value: 'unknown-value',
      refanged_value: 'unknown-value',
      indicator_type: 'N/A',
      valid: true,
    },
  ])

  assert.equal(detected.length, 1)
  assert.equal(detected[0].indicator_type, 'Url')
})

test('ignored items are hidden by default', () => {
  assert.equal(isIgnoredCollapsedByDefault(), true)
})

test('ignored items can be expanded', () => {
  assert.equal(toggleIgnoredExpanded(false), true)
  assert.equal(toggleIgnoredExpanded(true), false)
})

test('no valid IOCs uses the expected empty-state message', () => {
  const { detected } = splitDetectedAndIgnored([
    {
      original_value: 'hello world',
      refanged_value: 'hello world',
      indicator_type: null,
      valid: false,
      reason: 'unsupported_indicator',
    },
  ])

  assert.equal(detected.length, 0)
  assert.equal(DETECTED_EMPTY_MESSAGE, 'No supported IOCs were detected.')
})

test('raw unsupported_indicator is not displayed in friendly ignored reasons', () => {
  assert.equal(getFriendlyIgnoredReason('unsupported_indicator'), 'Ignored non-IOC text')
  assert.notEqual(getFriendlyIgnoredReason('unsupported_indicator'), 'unsupported_indicator')
})
