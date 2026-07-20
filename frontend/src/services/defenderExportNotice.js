import { WORKFLOW_MODE } from './workflowMode.js'
import { getDetectedSenderEmailAddresses } from './senderEmailWorkflow.js'

function countValidIndicators(indicators) {
  return (indicators || []).filter((indicator) => Boolean(indicator?.valid)).length
}

function countDefenderExportableIndicators(indicators) {
  return (indicators || []).filter((indicator) => {
    if (!indicator?.valid) {
      return false
    }

    return String(indicator?.indicator_type || '').trim().toLowerCase() !== 'senderemailaddress'
  }).length
}

function formatNoticeMessage(emailCount) {
  if (emailCount === 1) {
    return '1 sender email indicator was detected but is not included in the Defender CSV export because sender email addresses are not supported for Defender IOC import.'
  }

  return `${emailCount} email indicators were detected but will not be included in the Defender CSV export because sender email addresses are not supported for Defender IOC import.`
}

export function buildDefenderExportNotice({ workflowMode, indicators } = {}) {
  const normalizedWorkflowMode = String(workflowMode || '').trim().toLowerCase()
  if (normalizedWorkflowMode !== WORKFLOW_MODE.DEFENDER) {
    return null
  }

  const emailCount = getDetectedSenderEmailAddresses(indicators).length
  if (emailCount === 0) {
    return null
  }

  const totalDetected = countValidIndicators(indicators)
  const exportableCount = countDefenderExportableIndicators(indicators)

  return {
    totalDetected,
    exportableCount,
    emailCount,
    message: formatNoticeMessage(emailCount),
    countsText: `Detected indicators: ${totalDetected} · Exportable to Defender: ${exportableCount} · Excluded email addresses: ${emailCount}`,
  }
}