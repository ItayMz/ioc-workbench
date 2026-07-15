import assert from 'node:assert/strict'
import test from 'node:test'

import { downloadCsvContent } from './downloadFile.js'

function withDownloadMocks(runAssertions) {
  const originalBlob = globalThis.Blob
  const originalUrl = globalThis.URL
  const originalDocument = globalThis.document

  let capturedParts = null
  let capturedType = null

  class MockBlob {
    constructor(parts, options) {
      capturedParts = parts
      capturedType = options?.type
    }
  }

  const anchor = {
    href: '',
    download: '',
    clickCalled: false,
    click() {
      this.clickCalled = true
    },
  }

  globalThis.Blob = MockBlob
  globalThis.URL = {
    createObjectURL() {
      return 'blob:mock-url'
    },
    revokeObjectURL() {},
  }
  globalThis.document = {
    createElement(tagName) {
      assert.equal(tagName, 'a')
      return anchor
    },
    body: {
      appendChild(node) {
        assert.equal(node, anchor)
      },
      removeChild(node) {
        assert.equal(node, anchor)
      },
    },
  }

  try {
    runAssertions(() => ({
      payload: String(capturedParts?.[0] ?? ''),
      mimeType: capturedType,
      clicked: anchor.clickCalled,
    }))
  } finally {
    globalThis.Blob = originalBlob
    globalThis.URL = originalUrl
    globalThis.document = originalDocument
  }
}

test('downloadCsvContent prepends exactly one UTF-8 BOM when includeUtf8Bom is true', () => {
  withDownloadMocks((getResult) => {
    downloadCsvContent('type,value\nsha256,abc', 'crowdstrike.csv', { includeUtf8Bom: true })

    const result = getResult()
    assert.equal(result.mimeType, 'text/csv;charset=utf-8')
    assert.equal(result.clicked, true)
    assert.equal(result.payload.startsWith('\uFEFF'), true)
    assert.equal(result.payload.startsWith('\uFEFF\uFEFF'), false)
    assert.equal(result.payload, '\uFEFFtype,value\nsha256,abc')
  })
})

test('downloadCsvContent remains BOM-free by default', () => {
  withDownloadMocks((getResult) => {
    downloadCsvContent('type,value\nsha256,abc', 'plain.csv')

    const result = getResult()
    assert.equal(result.payload.startsWith('\uFEFF'), false)
    assert.equal(result.payload, 'type,value\nsha256,abc')
  })
})
