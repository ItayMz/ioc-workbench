import { useEffect, useRef, useState } from 'react'
import { DEFENDER_CATEGORIES } from '../services/defenderCategories.js'
import { WORKFLOW_MODE } from '../services/workflowMode.js'

function ControlPanel({
  rawText,
  lookbackDays,
  campaignName,
  defaultCategory,
  workflowMode,
  uploadSummary,
  processingInFlight,
  uploadingInFlight,
  exportInFlight,
  lookbackRefreshing,
  onRawTextChange,
  onLookbackChange,
  onCampaignNameChange,
  onDefaultCategoryChange,
  onWorkflowModeChange,
  onProcess,
  onUpload,
  onExport,
  onSecondaryExport,
  onClear,
  exportButtonLabel,
  exportDisabled,
  secondaryExportButtonLabel,
  secondaryExportDisabled,
  hasAccumulatedResult,
  backendConnected,
  backendActionsDisabled,
  showDefenderControls,
  crowdStrikeSeverity,
  crowdStrikeDescription,
  onCrowdStrikeSeverityChange,
  onCrowdStrikeDescriptionChange,
  onCrowdStrikeExport,
  crowdStrikeExportDisabled,
  clearVersion,
}) {
  const uploadRef = useRef(null)
  const [isDragOver, setIsDragOver] = useState(false)
  const isProcessingInputs = processingInFlight || uploadingInFlight

  useEffect(() => {
    setIsDragOver(false)
  }, [clearVersion])

  const onFilePicked = async (event) => {
    const files = Array.from(event.target.files || [])
    if (!files.length || backendActionsDisabled) {
      return
    }

    await onUpload(files)
    event.target.value = ''
  }

  const onDragOver = (event) => {
    event.preventDefault()

    if (backendActionsDisabled) {
      return
    }

    setIsDragOver(true)
  }

  const onDragLeave = (event) => {
    event.preventDefault()
    setIsDragOver(false)
  }

  const onDrop = async (event) => {
    event.preventDefault()
    setIsDragOver(false)

    if (backendActionsDisabled) {
      return
    }

    const files = Array.from(event.dataTransfer?.files || [])
    if (!files.length || backendActionsDisabled) {
      return
    }

    await onUpload(files)
  }

  return (
    <section className="card control-panel">
      <div className="panel-top">
        <h2>IOC Intake</h2>
        <p className="muted">Paste raw intel text or upload a CSV/TXT/XLSX file. Processing runs through the backend API.</p>
      </div>

      <textarea
        className="ioc-textarea"
        value={rawText}
        onChange={(event) => onRawTextChange(event.target.value)}
        placeholder="Paste IOC text here"
        disabled={isProcessingInputs}
      />

      {showDefenderControls && (
        <div className="control-row">
          <label className="field-label" htmlFor="campaignNameInput">Campaign name</label>
          <input
            id="campaignNameInput"
            className="campaign-input"
            type="text"
            value={campaignName}
            onChange={(event) => onCampaignNameChange(event.target.value)}
            placeholder="Optional campaign name"
            disabled={isProcessingInputs}
          />
        </div>
      )}

      <div className="control-row control-row-column">
        <label className="field-label">Workflow</label>
        <div className="workflow-selector" role="tablist" aria-label="Workflow selector">
          <button
            type="button"
            className={`workflow-badge-button${workflowMode === WORKFLOW_MODE.DEFENDER ? ' active' : ''}`}
            onClick={() => onWorkflowModeChange(WORKFLOW_MODE.DEFENDER)}
            disabled={isProcessingInputs}
          >
            Microsoft Defender
          </button>
          <button
            type="button"
            className={`workflow-badge-button${workflowMode === WORKFLOW_MODE.CROWDSTRIKE ? ' active' : ''}`}
            onClick={() => onWorkflowModeChange(WORKFLOW_MODE.CROWDSTRIKE)}
            disabled={isProcessingInputs}
          >
            CrowdStrike
          </button>
        </div>
      </div>

      {showDefenderControls && (
        <div className="control-row">
        <label className="field-label" htmlFor="lookbackSelect">Lookback</label>
        <select
          id="lookbackSelect"
          className="lookback-select"
          value={lookbackDays}
          onChange={(event) => onLookbackChange(Number(event.target.value))}
          disabled={isProcessingInputs || lookbackRefreshing}
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={180}>Last 180 days</option>
          <option value={365}>Last 365 days</option>
        </select>
        </div>
      )}

      {showDefenderControls && (
        <div className="control-row">
          <label className="field-label" htmlFor="defaultCategorySelect">Default Category</label>
          <select
            id="defaultCategorySelect"
            className="lookback-select"
            value={defaultCategory}
            onChange={(event) => onDefaultCategoryChange(event.target.value)}
            disabled={isProcessingInputs}
          >
            {DEFENDER_CATEGORIES.map((category) => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
        </div>
      )}

      {!showDefenderControls && (
        <>
          <div className="control-row">
            <label className="field-label" htmlFor="crowdstrikeSeverity">Severity</label>
            <select
              id="crowdstrikeSeverity"
              className="lookback-select"
              value={crowdStrikeSeverity}
              onChange={(event) => onCrowdStrikeSeverityChange(event.target.value)}
              disabled={isProcessingInputs}
            >
              <option value="high">high</option>
              <option value="medium">medium</option>
            </select>
          </div>

          <div className="control-row control-row-column">
            <label className="field-label" htmlFor="crowdstrikeDescription">Description</label>
            <textarea
              id="crowdstrikeDescription"
              className="ioc-textarea crowdstrike-description"
              value={crowdStrikeDescription}
              onChange={(event) => onCrowdStrikeDescriptionChange(event.target.value)}
              placeholder="Optional description applied to every exported row"
              disabled={isProcessingInputs}
            />
          </div>
        </>
      )}

      <div className="button-row">
        <button className="primary" type="button" onClick={onProcess} disabled={backendActionsDisabled}>
          {processingInFlight ? 'Processing...' : (hasAccumulatedResult ? 'Add IOCs' : 'Process IOCs')}
        </button>
        <button type="button" onClick={() => uploadRef.current?.click()} disabled={backendActionsDisabled}>
          {uploadingInFlight ? 'Processing files...' : (hasAccumulatedResult ? 'Add Files to Current Export' : 'Upload CSV/TXT/XLSX Files')}
        </button>
        {showDefenderControls && (
          <button type="button" onClick={onExport} disabled={exportDisabled}>
            {exportInFlight ? 'Generating export...' : exportButtonLabel}
          </button>
        )}
        {!showDefenderControls && (
          <button type="button" onClick={onCrowdStrikeExport} disabled={crowdStrikeExportDisabled}>
            Export CrowdStrike CSV
          </button>
        )}
        {!showDefenderControls && (
          <button type="button" onClick={onSecondaryExport} disabled={secondaryExportDisabled}>
            {secondaryExportButtonLabel}
          </button>
        )}
        <button type="button" className="button-clear" onClick={onClear} disabled={isProcessingInputs}>
          Clear
        </button>
      </div>

      {!showDefenderControls && (
        <p className="muted workflow-note">CrowdStrike workflow selected. Defender-specific outputs are hidden.</p>
      )}

      <div
        className={`drop-zone${isDragOver ? ' drop-zone-active' : ''}${backendActionsDisabled ? ' drop-zone-disabled' : ''}`}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        role="button"
        tabIndex={0}
        onClick={() => uploadRef.current?.click()}
        onKeyDown={(event) => {
          if (backendActionsDisabled) {
            return
          }

          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            uploadRef.current?.click()
          }
        }}
        aria-label="Drop CSV, TXT, or XLSX files here, or press Enter to browse"
      >
        <p><strong>Drag and drop CSV/TXT/XLSX files here</strong></p>
        <p className="muted">Supports multi-file drop and uses the same upload processing pipeline.</p>
        {!backendConnected && (
          <p className="muted">Upload processing is disabled until backend connection is available.</p>
        )}
      </div>

      {uploadSummary && (
        <div className="upload-summary" role="status" aria-live="polite">
          <p><strong>Files uploaded:</strong> {uploadSummary.filesUploaded}</p>
          <p><strong>IOCs extracted:</strong> {uploadSummary.iocsExtracted}</p>
          <p><strong>Campaign name detected:</strong> {uploadSummary.detectedCampaignName || 'None'}</p>
          {uploadSummary.warning && <p className="summary-warning">{uploadSummary.warning}</p>}
        </div>
      )}

      <input
        ref={uploadRef}
        type="file"
        accept=".csv,.txt,.xlsx"
        multiple
        onChange={onFilePicked}
        className="hidden-input"
        disabled={backendActionsDisabled}
      />
    </section>
  )
}

export default ControlPanel
