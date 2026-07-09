import { buildDetectionSummary } from '../services/summaryPresentation.js'

function SummaryCards({ summary }) {
  const detectionSummary = buildDetectionSummary(summary)
  if (!detectionSummary) {
    return null
  }

  return (
    <section className="card detection-summary" aria-live="polite">
      <div className="section-header">
        <h2>{detectionSummary.title}</h2>
      </div>

      <div className="summary-total-wrap">
        <article className="summary-item summary-item-total">
          <p>Total Detected</p>
          <strong>{detectionSummary.totalDetected}</strong>
        </article>
      </div>

      <div className="summary-grid">
        {detectionSummary.breakdown.map((item) => (
          <article key={item.label} className={`summary-item${item.isMuted ? ' summary-item-muted' : ''}`}>
            <p>{item.label}</p>
            <strong>{item.value}</strong>
          </article>
        ))}
      </div>

      <div className="summary-meta-row">
        {detectionSummary.meta.map((entry) => (
          <p key={entry.label} className="summary-meta">
            <span>{entry.label}:</span> <strong>{entry.value}</strong>
          </p>
        ))}
      </div>
    </section>
  )
}

export default SummaryCards
