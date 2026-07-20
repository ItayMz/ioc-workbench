import { useEffect, useRef, useState } from 'react'

import { getVisibleKqlCards } from '../services/kqlCardsPresentation.js'
import Icon from './Icon.jsx'

const KQL_COPY_RESET_MS = 1800

function KqlCards({ queries, onQueryCopied }) {
  const [copiedByCard, setCopiedByCard] = useState({})
  const copyResetTimersRef = useRef({})
  const queryCards = queries ? getVisibleKqlCards(queries) : []

  useEffect(() => {
    const timers = copyResetTimersRef.current

    return () => {
      Object.values(timers).forEach(clearTimeout)
    }
  }, [])

  if (!queryCards.length) {
    return null
  }

  const copyQuery = async (cardKey, queryText) => {
    try {
      await navigator.clipboard.writeText(queryText)
      onQueryCopied?.()
      setCopiedByCard((current) => ({
        ...current,
        [cardKey]: true,
      }))

      if (copyResetTimersRef.current[cardKey]) {
        clearTimeout(copyResetTimersRef.current[cardKey])
      }

      copyResetTimersRef.current[cardKey] = setTimeout(() => {
        setCopiedByCard((current) => ({
          ...current,
          [cardKey]: false,
        }))
      }, KQL_COPY_RESET_MS)
    } catch {
      // Browsers can block clipboard in non-secure contexts.
    }
  }

  return (
    <section className="kql-grid">
      {queryCards.map((card) => (
        <article key={card.key} className="card kql-card">
          <div className="section-header">
            <h2>{card.title}</h2>
            <div className="kql-copy-actions">
              {copiedByCard[card.key] && <span className="kql-copy-confirmation">Copied!</span>}
              <button type="button" onClick={() => copyQuery(card.key, card.query)}>
                <Icon name="copy" className="inline-icon" /> {copiedByCard[card.key] ? 'Copied ✓' : 'Copy KQL'}
              </button>
            </div>
          </div>
          <pre className="query-block">{card.query}</pre>
        </article>
      ))}
    </section>
  )
}

export default KqlCards
