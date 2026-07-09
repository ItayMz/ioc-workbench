# TSOC IOC Portal

## Current Status

Version: v1.0.0-rc1

## Project Description

TSOC IOC Portal is now a full-stack IOC workflow application with a React frontend and a FastAPI backend. The frontend is a thin client that sends IOC payloads to the backend API. The backend remains the source of truth for parsing, validation, refang, normalization, deduplication, KQL generation, summary generation, and Defender export data.

## What this project demonstrates

- SOC workflow understanding
- API-driven IOC normalization and classification
- Microsoft Defender CSV formatting
- Defender Advanced Hunting KQL generation
- Backend validation and error handling
- Modern frontend dashboard composition with reusable components
- Automated regression coverage for backend parsing and export logic

## Features

- Parse mixed IOC input from pasted text
- Upload one or more CSV/TXT files and process through backend API
- Generate processing summary cards from backend response
- Produce KQL cards with lookback-aware queries
- Export Defender CSV from backend-provided IOC output data
- Show clear loading and error states during API operations
- Extract IOC values from CSV value column and detect campaign name from CSV event_info
- Support optional manual campaign name input that overrides detected campaign names

## Architecture

- Backend: FastAPI under backend/app
- Frontend: React under frontend
- Communication: HTTP API calls from frontend to backend

Backend modules retained as core source of truth:

- parser
- kql_builder
- parse route/API
- backend tests

## Frontend structure

Frontend logic is separated into:

- frontend/src/components
- frontend/src/services
- frontend/src/styles

## Setup

Backend and frontend must both be running for normal use.

### Frontend API configuration

The React frontend reads the backend base URL from:

- VITE_API_BASE_URL

Example file:

- frontend/.env.example

Default fallback is http://localhost:8000 if the environment variable is not set.

### Start backend

1. Open a terminal in backend.
2. Install Python dependencies if needed.
3. Run:

- uvicorn app.main:app --reload

The API is available by default at http://127.0.0.1:8000.

### Start frontend

1. Open a second terminal in frontend.
2. Install dependencies:

- npm install

3. Start development server:

- npm run dev

Frontend runs by default at http://127.0.0.1:5173.

### Optional Windows dev launcher

You can start backend and frontend in separate PowerShell windows with:

- .\scripts\dev.ps1

## Usage

1. Open the frontend URL in a browser.
2. Paste IOC text or upload CSV/TXT files.
3. Select lookback window.
4. Optionally enter a campaign name.
5. Click Process IOCs.
6. For file uploads, review the upload summary (files uploaded, IOCs extracted, detected campaign name).
7. Review summary cards, parsed IOC results, and generated KQL cards.
8. Export Defender CSV when needed.

The frontend does not perform IOC parsing logic itself. IOC processing is delegated to backend API endpoints.

## Manual validation checklist

- Paste mixed IOC input and confirm classification results.
- Verify KQL cards appear only for relevant IOC types.
- Change the lookback value and confirm KQL updates.
- Copy each query and confirm clipboard content.
- Verify CSV export still works as expected.

## Frontend validation checklist

- Start backend and frontend servers.
- Paste mixed IOCs and verify parse response renders in UI.
- Upload CSV/TXT and verify parsing works.
- Confirm Defender CSV export works.
- Confirm KQL cards generate correctly.
- Confirm lookback selector updates KQL output.
- Confirm copy buttons work on KQL cards.
- Confirm loading state appears during requests.
- Confirm clear error messages are shown for API failures.

## Testing

Backend tests remain in place and should not be removed.

Run the full backend test suite:

- cd backend
- pytest

## Screenshots / GIF

Screenshot and GIF assets are not included yet. A placeholder will be added in a future update once UI captures are ready.

## Scope notes

This release does not add authentication, database storage, external threat intel lookups, or third-party integrations.
