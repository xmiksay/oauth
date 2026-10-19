/** An absolute http(s) URL — never follow a `javascript:` / `data:` URL whatever a server sends. */
export function isWebUrl(raw: string): boolean {
  try {
    const { protocol } = new URL(raw)
    return protocol === 'https:' || protocol === 'http:'
  } catch {
    return false
  }
}

/**
 * Full-page navigation away from the SPA (an app's redirect URI, an identity provider).
 * A module of its own so tests can mock it: jsdom's `location.assign` can't be spied on.
 */
export function navigateTo(url: string): void {
  window.location.assign(url)
}
