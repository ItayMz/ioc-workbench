function KqlCards({ queries }) {
  if (!queries) {
    return null
  }

  const queryEntries = Object.entries(queries).filter(([, value]) => value?.query)
  if (!queryEntries.length) {
    return null
  }

  const copyQuery = async (queryText) => {
    try {
      await navigator.clipboard.writeText(queryText)
    } catch {
      // Browsers can block clipboard in non-secure contexts.
    }
  }

  return (
    <section className="kql-grid">
      {queryEntries.map(([key, value]) => (
        <article key={key} className="card kql-card">
          <div className="section-header">
            <h2>{key.toUpperCase()} Query</h2>
            <button type="button" onClick={() => copyQuery(value.query)}>Copy KQL</button>
          </div>
          <div className="meta-row">
            <span className="chip">IOC count: {value.count}</span>
            <span className="chip">Lookback: {value.lookbackDays}d</span>
            <span className="chip">Tables: {value.tables.join(', ')}</span>
          </div>
          <pre className="query-block">{value.query}</pre>
        </article>
      ))}
    </section>
  )
}

export default KqlCards
