import { useEffect, useRef, useState } from 'react'

const COPY_RESET_MS = 1800

function CrowdStrikeQueryCard({ queryData, onCopySuccess }) {
  const [copied, setCopied] = useState(false)
  const resetTimerRef = useRef(null)

  useEffect(() => () => {
    if (resetTimerRef.current) {
      clearTimeout(resetTimerRef.current)
    }
  }, [])

  const copyQuery = async () => {
    try {
      await navigator.clipboard.writeText(queryData.query)
      setCopied(true)
      onCopySuccess?.()

      if (resetTimerRef.current) {
        clearTimeout(resetTimerRef.current)
      }

      resetTimerRef.current = setTimeout(() => {
        setCopied(false)
      }, COPY_RESET_MS)
    } catch {
      // Browsers can block clipboard in non-secure contexts.
    }
  }

  return (
    <article className="card kql-card" aria-live="polite">
      <div className="section-header">
        <h2>Advanced Event Search Query</h2>
        <div className="kql-copy-actions">
          {copied && <span className="kql-copy-confirmation">Copied!</span>}
          <button type="button" onClick={copyQuery}>
            {copied ? 'Copied ✓' : 'Copy Query'}
          </button>
        </div>
      </div>
      <p className="muted">Search all detected indicators in CrowdStrike Advanced Event Search.</p>
      <div className="meta-row">
        <span className="chip">IOC count: {queryData.totalUniqueIocCount}</span>
        <span className="chip">IOC types: {queryData.uniqueTypeCount}</span>
      </div>
      <pre className="query-block">{queryData.query}</pre>
    </article>
  )
}

export default CrowdStrikeQueryCard