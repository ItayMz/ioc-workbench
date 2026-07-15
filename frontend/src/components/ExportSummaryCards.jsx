function ExportSummaryCards({ summaries }) {
  if (!summaries.length) {
    return null
  }

  return (
    <section className="card export-summary-card" aria-live="polite">
      <div className="section-header">
        <h2>Export Summary</h2>
      </div>
      <div className="export-summary-grid">
        {summaries.map((entry) => (
          <article key={entry.type} className="summary-item">
            <p>{entry.title}</p>
            <strong>{entry.countLabel ? `${entry.count} ${entry.countLabel}` : entry.count}</strong>
            <p className="summary-meta">Filename: <strong>{entry.filename}</strong></p>
          </article>
        ))}
      </div>
    </section>
  )
}

export default ExportSummaryCards
