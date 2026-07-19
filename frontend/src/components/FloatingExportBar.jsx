import Icon from './Icon.jsx'

function FloatingExportBar({
  visible,
  isDefenderMode,
  totalIndicators,
  queryCount,
  crowdStrikeEligibleCount,
  qradarEligibleCount,
  onDefenderExport,
  onCrowdStrikeExport,
  onQradarExport,
  onBackToTop,
  defenderExportDisabled,
  crowdStrikeExportDisabled,
  qradarExportDisabled,
  defenderExportLabel,
  qradarExportLabel,
}) {
  const statusText = isDefenderMode
    ? `${totalIndicators} indicators${queryCount > 0 ? ` · ${queryCount} queries` : ''}`
    : `${totalIndicators} indicators · ${crowdStrikeEligibleCount} CrowdStrike eligible · ${qradarEligibleCount} QRadar eligible`

  return (
    <section
      className={`floating-export-bar${visible ? ' visible' : ' hidden'}`}
      aria-label="Quick export actions"
    >
      <div className="floating-export-status" aria-live="off">
        <Icon name="summary" className="inline-icon" />
        <span className="floating-export-ready">Ready for export</span>
        <span className="floating-export-meta">{statusText}</span>
      </div>

      <div className="floating-export-actions">
        {isDefenderMode ? (
          <button type="button" onClick={onDefenderExport} disabled={defenderExportDisabled}>
            <Icon name="export" className="inline-icon" /> {defenderExportLabel}
          </button>
        ) : (
          <>
            <button type="button" onClick={onCrowdStrikeExport} disabled={crowdStrikeExportDisabled}>
              <Icon name="export" className="inline-icon" /> Export CrowdStrike CSV
            </button>
            <button type="button" onClick={onQradarExport} disabled={qradarExportDisabled}>
              <Icon name="qradar" className="inline-icon" /> {qradarExportLabel}
            </button>
          </>
        )}

        <button
          type="button"
          className="floating-export-back-to-top"
          onClick={onBackToTop}
          aria-label="Back to top"
        >
          <Icon name="arrow-up" className="inline-icon" />
        </button>
      </div>
    </section>
  )
}

export default FloatingExportBar
