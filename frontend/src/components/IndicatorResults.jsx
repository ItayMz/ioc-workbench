import { useState } from 'react'
import {
  DETECTED_EMPTY_MESSAGE,
  isIgnoredCollapsedByDefault,
  splitDetectedAndIgnored,
  toggleIgnoredExpanded,
} from '../services/indicatorPresentation.js'

function IndicatorResults({ indicators }) {
  const { detected, ignored } = splitDetectedAndIgnored(indicators)
  const [isIgnoredExpanded, setIsIgnoredExpanded] = useState(!isIgnoredCollapsedByDefault())

  return (
    <section className="card">
      <div className="section-header">
        <h2>Detected Indicators</h2>
        <span className="chip">{detected.length} indicators</span>
      </div>

      {detected.length ? (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Original</th>
                <th>Refanged</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {detected.map((ioc, index) => (
                <tr key={`${ioc.refanged_value || ioc.original_value}-${index}`}>
                  <td>{ioc.original_value}</td>
                  <td>{ioc.refanged_value}</td>
                  <td>{ioc.indicator_type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted indicator-empty-state">{DETECTED_EMPTY_MESSAGE}</p>
      )}

      {ignored.length > 0 && (
        <div className="ignored-panel">
          <button
            type="button"
            className="ignored-toggle"
            onClick={() => setIsIgnoredExpanded((current) => toggleIgnoredExpanded(current))}
          >
            {isIgnoredExpanded ? 'Hide ignored items' : 'Show ignored items'}
          </button>

          {isIgnoredExpanded && (
            <div className="table-wrapper ignored-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Original value</th>
                    <th>Refanged value</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {ignored.map((item, index) => (
                    <tr key={`${item.refanged_value || item.original_value || 'ignored'}-${index}`}>
                      <td>{item.original_value || '-'}</td>
                      <td>{item.refanged_value || '-'}</td>
                      <td>{item.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

export default IndicatorResults
