import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const indicatorResultsPath = resolve(process.cwd(), 'src/components/IndicatorResults.jsx')
const appStylesPath = resolve(process.cwd(), 'src/styles/app.css')

test('Detected Indicators controls keep expected wrapper classes for aligned toggle and Copy All layout', () => {
  const componentSource = readFileSync(indicatorResultsPath, 'utf8')

  assert.equal(componentSource.includes('className="indicator-controls"'), true)
  assert.equal(componentSource.includes('className="indicator-mode-toggle"'), true)
  assert.equal(componentSource.includes('className="copy-all-button"'), true)
})

test('responsive control wrapper styles exist for clean wrapping on mobile', () => {
  const cssSource = readFileSync(appStylesPath, 'utf8')

  assert.equal(cssSource.includes('.indicator-controls {'), true)
  assert.equal(cssSource.includes('.copy-all-button {'), true)
  assert.equal(cssSource.includes('@media (max-width: 720px)'), true)
})
