/** The build serving this page: version from `Cargo.toml`, short git commit (or `unknown`). */
export interface BuildInfo {
  version: string
  commit: string
}

/**
 * The build the server wrote into `index.html` (`<meta name="oauth-build" content="<version>+<commit>">`,
 * see `spa.rs`), so the SPA can never claim another build than the binary serving it. `null`
 * without one (the Vite dev server serves its own `index.html`) or when malformed. Split at the
 * last `+`: the commit is hex, while a version may carry semver build metadata.
 */
export function buildFromMeta(doc: Pick<Document, 'querySelector'> = document): BuildInfo | null {
  const content = doc.querySelector('meta[name="oauth-build"]')?.getAttribute('content') ?? ''
  const at = content.lastIndexOf('+')
  if (at <= 0 || at === content.length - 1) return null
  return { version: content.slice(0, at), commit: content.slice(at + 1) }
}
