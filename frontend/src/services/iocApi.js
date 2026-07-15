import { parseUploadedFiles, resolveCampaignName } from './uploadParser.js'
import { downloadCsvContent } from './downloadFile.js'
import { buildCampaignExportFilename } from './exportNaming.js'

const API_BASE_URL = (import.meta.env && import.meta.env.VITE_API_BASE_URL) || 'http://localhost:8000'
const DEFENDER_FILENAME_SUFFIX = 'defender.csv'
const DEFENDER_FILENAME_FALLBACK = 'defender-iocs.csv'

async function parseJsonResponse(response) {
  let payload = null

  try {
    payload = await response.json()
  } catch {
    payload = null
  }

  if (!response.ok) {
    const detail = payload?.detail || 'Request failed. Check backend logs for details.'
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }

  return payload
}

export async function parseIocs(rawText, lookbackDays, campaignName = null) {
  const resolvedCampaignName = resolveCampaignName(campaignName, null)

  const response = await fetch(`${API_BASE_URL}/parse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      raw_text: rawText,
      lookbackDays,
      campaignName: resolvedCampaignName,
    }),
  })

  return parseJsonResponse(response)
}

export async function checkBackendHealth() {
  const response = await fetch(`${API_BASE_URL}/`, {
    method: 'GET',
  })

  const payload = await parseJsonResponse(response)
  return payload?.status === 'ok'
}

export async function parseIocsWithMetadata({ rawText, lookbackDays, campaignName = null, defaultCategory = null, iocMetadata = null }) {
  const resolvedCampaignName = resolveCampaignName(campaignName, null)

  const response = await fetch(`${API_BASE_URL}/parse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      raw_text: rawText,
      lookbackDays,
      campaignName: resolvedCampaignName,
      defaultCategory,
      iocMetadata,
    }),
  })

  return parseJsonResponse(response)
}

export async function uploadFiles(files, lookbackDays, manualCampaignName = null, defaultCategory = null) {
  const parsedUploads = await parseUploadedFiles(files)
  const manualOverrideCampaignName = resolveCampaignName(manualCampaignName, null)
  const effectiveCampaignName = resolveCampaignName(
    manualCampaignName,
    parsedUploads.summary.detectedCampaignName,
  )

  const requestPayload = {
    rawText: parsedUploads.rawText,
    lookbackDays,
    campaignName: manualOverrideCampaignName,
    defaultCategory,
    iocMetadata: parsedUploads.iocMetadata,
  }

  const data = await parseIocsWithMetadata(requestPayload)

  return {
    data,
    iocMetadata: parsedUploads.iocMetadata,
    requestPayload,
    summary: {
      ...parsedUploads.summary,
      effectiveCampaignName,
    },
  }
}

export async function exportDefenderCsv({ rawText, lookbackDays, campaignName = null, defaultCategory = null, iocMetadata = null }) {
  const resolvedCampaignName = resolveCampaignName(campaignName, null)

  const response = await fetch(`${API_BASE_URL}/export/csv`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      raw_text: rawText,
      lookbackDays,
      campaignName: resolvedCampaignName,
      defaultCategory,
      iocMetadata,
    }),
  })

  if (!response.ok) {
    const detail = await response.text()
    throw new Error(detail || 'Failed to export Defender CSV.')
  }

  const csvContent = await response.text()
  const filename = buildCampaignExportFilename(resolvedCampaignName, DEFENDER_FILENAME_SUFFIX, DEFENDER_FILENAME_FALLBACK)
  downloadCsvContent(csvContent, filename)

  return {
    filename,
  }
}
