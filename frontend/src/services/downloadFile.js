const UTF8_BOM = '\uFEFF'

export function downloadFile({
  content,
  filename,
  mimeType = 'text/csv;charset=utf-8',
  includeUtf8Bom = false,
}) {
  const normalizedContent = String(content ?? '')
  const payload = includeUtf8Bom ? `${UTF8_BOM}${normalizedContent}` : normalizedContent

  const blob = new Blob([payload], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

export function downloadCsvContent(content, filename, { includeUtf8Bom = false } = {}) {
  downloadFile({
    content,
    filename,
    mimeType: 'text/csv;charset=utf-8',
    includeUtf8Bom,
  })
}
