import { describe, expect, it } from 'vitest'
import { buildFromMeta } from './build'

function docWith(html: string): Document {
  const doc = document.implementation.createHTMLDocument('t')
  doc.head.innerHTML = html
  return doc
}

describe('buildFromMeta', () => {
  it('splits version and commit', () => {
    expect(buildFromMeta(docWith('<meta name="oauth-build" content="0.1.0+0123456789ab">'))).toEqual({
      version: '0.1.0',
      commit: '0123456789ab',
    })
  })

  it('splits at the last plus, keeping semver build metadata in the version', () => {
    expect(buildFromMeta(docWith('<meta name="oauth-build" content="1.0.0+x.1+unknown">'))).toEqual({
      version: '1.0.0+x.1',
      commit: 'unknown',
    })
  })

  it('is null without a usable meta', () => {
    expect(buildFromMeta(docWith(''))).toBeNull()
    for (const content of ['', '0.1.0', '+abc', '0.1.0+']) {
      expect(buildFromMeta(docWith(`<meta name="oauth-build" content="${content}">`))).toBeNull()
    }
  })
})
