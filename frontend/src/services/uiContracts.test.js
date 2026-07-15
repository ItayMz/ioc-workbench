import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const indicatorResultsPath = resolve(process.cwd(), 'src/components/IndicatorResults.jsx')
const kqlCardsPath = resolve(process.cwd(), 'src/components/KqlCards.jsx')
const senderEmailInfoCardPath = resolve(process.cwd(), 'src/components/SenderEmailInfoCard.jsx')
const crowdStrikeQueryCardPath = resolve(process.cwd(), 'src/components/CrowdStrikeQueryCard.jsx')
const crowdStrikeResultsPath = resolve(process.cwd(), 'src/components/CrowdStrikeResults.jsx')
const controlPanelPath = resolve(process.cwd(), 'src/components/ControlPanel.jsx')
const appPath = resolve(process.cwd(), 'src/App.jsx')
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

test('KQL cards provide temporary copied state UI and restore button text after timeout', () => {
  const source = readFileSync(kqlCardsPath, 'utf8')

  assert.equal(source.includes("'Copy KQL'"), true)
  assert.equal(source.includes("'Copied ✓'"), true)
  assert.equal(source.includes("Copied!"), true)
  assert.equal(source.includes('KQL_COPY_RESET_MS = 1800'), true)
  assert.equal(source.includes('setTimeout(() => {'), true)
})

test('KQL copy flow does not use alert and keeps per-card copied state keyed by card key', () => {
  const source = readFileSync(kqlCardsPath, 'utf8')

  assert.equal(source.includes('alert('), false)
  assert.equal(source.includes('[cardKey]: true'), true)
  assert.equal(source.includes('[cardKey]: false'), true)
  assert.equal(source.includes('catch {'), true)
})

test('sender email workflow card includes required title, guidance, and Copy Emails button', () => {
  const source = readFileSync(senderEmailInfoCardPath, 'utf8')

  assert.equal(source.includes('Sender Email Addresses Detected'), true)
  assert.equal(source.includes('Copy Emails'), true)
  assert.equal(source.includes('{message}'), true)
  assert.equal(source.includes('sender-email-info-card sender-email-info-card-info'), true)
})

test('workflow selector supports Microsoft Defender and CrowdStrike only', () => {
  const source = readFileSync(controlPanelPath, 'utf8')

  assert.equal(source.includes('id="workflowModeSelect"'), true)
  assert.equal(source.includes('Microsoft Defender'), true)
  assert.equal(source.includes('CrowdStrike'), true)
  assert.equal(source.includes('QRadar'), false)
})

test('App wires workflow mode to gate Defender KQL cards and show CrowdStrike query results', () => {
  const source = readFileSync(appPath, 'utf8')

  assert.equal(source.includes('const [workflowMode, setWorkflowMode] = useState(WORKFLOW_MODE.DEFENDER)'), true)
  assert.equal(source.includes('workflowPresentation.isDefender ? ('), true)
  assert.equal(source.includes('<KqlCards queries={parseResult.kqlQueries} />'), true)
  assert.equal(source.includes('<CrowdStrikeResults indicators={parseResult.indicators} />'), true)
  assert.equal(source.includes('setWorkflowMode(WORKFLOW_MODE.DEFENDER)'), true)
})

test('CrowdStrike query card includes required title description metadata and Copy Query button', () => {
  const source = readFileSync(crowdStrikeQueryCardPath, 'utf8')

  assert.equal(source.includes('Advanced Event Search Query'), true)
  assert.equal(source.includes('Search all detected indicators in CrowdStrike Advanced Event Search.'), true)
  assert.equal(source.includes('Copy Query'), true)
  assert.equal(source.includes('IOC count:'), true)
  assert.equal(source.includes('IOC types:'), true)
})

test('CrowdStrike query copy payload exactly matches the displayed query string', () => {
  const source = readFileSync(crowdStrikeQueryCardPath, 'utf8')

  assert.equal(source.includes('navigator.clipboard.writeText(queryData.query)'), true)
  assert.equal(source.includes('<pre className="query-block">{queryData.query}</pre>'), true)
})

test('CrowdStrike results renders empty-state message when no valid indicators are available', () => {
  const source = readFileSync(crowdStrikeResultsPath, 'utf8')

  assert.equal(source.includes('if (!queryData)'), true)
  assert.equal(source.includes('No valid indicators are currently available for a CrowdStrike Advanced Event Search query.'), true)
})
