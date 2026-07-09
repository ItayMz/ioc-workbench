import assert from 'node:assert/strict'
import test from 'node:test'

import {
  DEFAULT_DEFENDER_CATEGORY,
  DEFENDER_CATEGORIES,
  normalizeDefaultCategory,
} from './defenderCategories.js'

test('supported Defender categories include Malware default', () => {
  assert.equal(DEFAULT_DEFENDER_CATEGORY, 'Malware')
  assert.equal(DEFENDER_CATEGORIES.includes('Malware'), true)
})

test('normalizeDefaultCategory keeps supported values', () => {
  assert.equal(normalizeDefaultCategory('Ransomware'), 'Ransomware')
})

test('normalizeDefaultCategory falls back to Malware when value is missing', () => {
  assert.equal(normalizeDefaultCategory(null), 'Malware')
  assert.equal(normalizeDefaultCategory(''), 'Malware')
})

test('normalizeDefaultCategory falls back to Malware when value is invalid', () => {
  assert.equal(normalizeDefaultCategory('TotallyInvalidCategory'), 'Malware')
})
