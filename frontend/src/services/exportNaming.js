function sanitizeCampaignName(name) {
  return String(name || '')
    .trim()
    .replace(/[\\/:*?"<>|\x00-\x1f]/g, '-')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-. ]+|[-. ]+$/g, '')
}

export function buildCampaignExportFilename(campaignName, suffix, fallbackName) {
  const sanitized = sanitizeCampaignName(campaignName)
  if (!sanitized) {
    return fallbackName
  }

  return `${sanitized}-${suffix}`
}
