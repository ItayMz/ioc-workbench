import CrowdStrikeQueryCard from './CrowdStrikeQueryCard'
import { buildCrowdStrikeAdvancedEventSearchQuery } from '../services/crowdstrikeQueryBuilder.js'

function CrowdStrikeResults({ indicators, onQueryCopied }) {
  const queryData = buildCrowdStrikeAdvancedEventSearchQuery(indicators)

  return (
    <>
      {queryData ? (
        <section className="kql-grid">
          <CrowdStrikeQueryCard queryData={queryData} onCopySuccess={onQueryCopied} />
        </section>
      ) : (
        <section className="card workflow-placeholder-card" aria-live="polite">
          <div className="section-header">
            <h2>CrowdStrike Workflow</h2>
          </div>
          <p className="muted">No CrowdStrike sweep query available.</p>
        </section>
      )}

    </>
  )
}

export default CrowdStrikeResults