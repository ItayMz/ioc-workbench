import { useEffect, useRef, useState } from 'react'

import { buildSenderEmailCopyPayload } from '../services/senderEmailWorkflow.js'

const COPY_RESET_MS = 1800

function SenderEmailInfoCard({ emailAddresses }) {
  const [copied, setCopied] = useState(false)
  const resetTimerRef = useRef(null)

  useEffect(() => () => {
    if (resetTimerRef.current) {
      clearTimeout(resetTimerRef.current)
    }
  }, [])

  const copyEmails = async () => {
    const payload = buildSenderEmailCopyPayload(emailAddresses)
    if (!payload) {
      return
    }

    try {
      await navigator.clipboard.writeText(payload)
      setCopied(true)

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
    <section className="card sender-email-info-card sender-email-info-card-info" aria-live="polite">
      <div className="section-header">
        <h2>Sender Email Addresses Detected</h2>
        <button type="button" onClick={copyEmails} disabled={!emailAddresses.length}>
          {copied ? 'Copied ✓' : 'Copy Emails'}
        </button>
      </div>

      <p className="muted sender-email-message">
        The following sender email address(es) were detected. Continue the investigation in Microsoft Defender Explorer under Email &amp; Collaboration, and perform any required blocking there.
      </p>

      <pre className="sender-email-list">{emailAddresses.join('\n')}</pre>
    </section>
  )
}

export default SenderEmailInfoCard
