import { useState, type FormEvent } from 'react'
import { assessPhpVersion, type AssessmentStatus, type VersionAssessment } from './assessment'
import { PHP_SECURITY_ADVISORY } from './data/advisories'
import './App.css'

const statusLabels: Record<AssessmentStatus, string> = {
  POTENTIALLY_AFFECTED: 'Potentially affected',
  UPSTREAM_PATCHED_VERSION: 'Upstream fixed release',
  LEGACY_UNVERIFIED: 'Legacy / vendor check needed',
  UNKNOWN: 'Unknown',
}

interface PublicScanResult {
  status: 'ASSESSED' | 'INCONCLUSIVE'
  phpVersion: string | null
  summary: string
  evidence: string
  httpStatus: number
  versionAssessment: VersionAssessment | null
}

function isAssessmentStatus(value: unknown): value is AssessmentStatus {
  return value === 'POTENTIALLY_AFFECTED'
    || value === 'UPSTREAM_PATCHED_VERSION'
    || value === 'LEGACY_UNVERIFIED'
    || value === 'UNKNOWN'
}

function isVersionAssessment(value: unknown): value is VersionAssessment {
  if (typeof value !== 'object' || value === null) return false
  const assessment = value as Record<string, unknown>
  if (
    typeof assessment.input !== 'string'
    || !(typeof assessment.version === 'string' || assessment.version === null)
    || !isAssessmentStatus(assessment.status)
    || typeof assessment.summary !== 'string'
    || typeof assessment.recommendation !== 'string'
    || typeof assessment.confidenceExplanation !== 'string'
    || !Array.isArray(assessment.vulnerabilities)
  ) {
    return false
  }

  return assessment.vulnerabilities.every((entry: unknown) => {
    if (typeof entry !== 'object' || entry === null) return false
    const vulnerability = entry as Record<string, unknown>
    return typeof vulnerability.cveId === 'string'
      && typeof vulnerability.title === 'string'
      && isAssessmentStatus(vulnerability.status)
      && typeof vulnerability.evidence === 'string'
      && typeof vulnerability.recommendation === 'string'
  })
}

function isPublicScanResult(value: unknown): value is PublicScanResult {
  if (typeof value !== 'object' || value === null) return false
  const result = value as Record<string, unknown>
  return (result.status === 'ASSESSED' || result.status === 'INCONCLUSIVE')
    && (typeof result.phpVersion === 'string' || result.phpVersion === null)
    && typeof result.summary === 'string'
    && typeof result.evidence === 'string'
    && typeof result.httpStatus === 'number'
    && (result.versionAssessment === null || isVersionAssessment(result.versionAssessment))
}

function StatusMark({ status }: { status: AssessmentStatus }) {
  return <span className={`status-mark status-mark--${status.toLowerCase()}`} aria-hidden="true">
    {status === 'UPSTREAM_PATCHED_VERSION' ? '✓' : status === 'POTENTIALLY_AFFECTED' ? '!' : '?'}
  </span>
}

function PublicWebsiteCheck() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<PublicScanResult | null>(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const submittedUrl = url.trim()

    if (!submittedUrl) {
      setResult(null)
      setError('Enter an HTTPS website URL to check.')
      return
    }

    setIsLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: submittedUrl }),
      })
      let payload: unknown
      try {
        payload = await response.json()
      } catch {
        setError('The assessment service returned an invalid response.')
        return
      }

      if (!response.ok) {
        const message = typeof payload === 'object' && payload !== null
          && 'error' in payload && typeof payload.error === 'string'
          ? payload.error
          : 'The website check could not be completed.'
        setError(message)
        return
      }
      if (!isPublicScanResult(payload)) {
        setError('The assessment service returned an invalid response.')
        return
      }

      setResult(payload)
    } catch {
      setError('Unable to contact the assessment service. Please try again later.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <section className="public-check" aria-labelledby="public-check-heading">
      <div className="public-check__heading">
        <div>
          <p className="eyebrow"><span className="eyebrow-line" /> ALLOWLISTED HOSTS ONLY</p>
          <h2 id="public-check-heading">Public website check</h2>
          <p className="public-check__intro">
            Request public response headers from explicitly enabled developer-controlled websites.
            This is a preliminary signal, not a server verification.
          </p>
        </div>
        <span className="public-check__badge"><span className="offline-dot" /> HEAD request only</span>
      </div>

      <form className="public-check__form" onSubmit={handleSubmit} noValidate>
        <label htmlFor="website-url">Website URL</label>
        <div className="form-controls">
          <div className={`input-wrap${error ? ' input-wrap--error' : ''}`}>
            <input
              id="website-url"
              name="website-url"
              type="url"
              inputMode="url"
              autoComplete="url"
              placeholder="https://your-domain.com"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value)
                if (error) setError('')
              }}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'website-error website-help' : 'website-help'}
            />
          </div>
          <button className="submit-button" type="submit" disabled={isLoading}>
            {isLoading ? <><span className="loading-spinner" aria-hidden="true" /> Checking…</> : <>Check website <span aria-hidden="true">→</span></>}
          </button>
        </div>
        {error && <p className="input-error" id="website-error" role="alert">{error}</p>}
        <p className="field-help" id="website-help">
          HTTPS on port 443 only. Only exact hostnames configured by the site operator can be checked.
        </p>
      </form>

      {result && (
        <section className="public-result" aria-live="polite" aria-labelledby="public-result-heading">
          <div className="public-result__top">
            <div>
              <p className="eyebrow">Preliminary result · HTTP {result.httpStatus}</p>
              <h3 id="public-result-heading">
                {result.phpVersion ? <>PHP <code>{result.phpVersion}</code></> : 'No version evidence'}
              </h3>
            </div>
            <span className={`public-result__status public-result__status--${result.status.toLowerCase()}`}>
              {result.status === 'ASSESSED' ? 'Version evidence found' : 'Inconclusive'}
            </span>
          </div>
          <p className="public-result__summary">{result.summary}</p>
          {result.versionAssessment && (
            <div className="cve-list">
              {result.versionAssessment.vulnerabilities.map((vulnerability) => (
                <article className="cve-card" key={vulnerability.cveId}>
                  <div className="cve-card__topline">
                    <span className="cve-id">{vulnerability.cveId}</span>
                    <span className={`cve-status cve-status--${vulnerability.status.toLowerCase()}`}>
                      {statusLabels[vulnerability.status]}
                    </span>
                  </div>
                  <h3>{vulnerability.title}</h3>
                  <p>{vulnerability.evidence}</p>
                  <p className="recommendation"><strong>Recommended next step:</strong> {vulnerability.recommendation}</p>
                </article>
              ))}
            </div>
          )}
          <div className="public-result__evidence">
            <strong>Evidence &amp; confidence</strong>
            <p>{result.evidence}</p>
            <p>
              The check makes one non-invasive HEAD request to the site root and does not follow redirects.
              Headers can be spoofed. Vendor security patches may be backported without changing the reported version.
              No vulnerability has been confirmed.
            </p>
          </div>
          {result.status === 'INCONCLUSIVE' && (
            <p className="public-result__future">
              A future verified server diagnostic would be needed to establish the runtime and package patch status.
            </p>
          )}
          <a className="source-link" href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
            Official PHP advisory <span aria-hidden="true">↗</span>
          </a>
        </section>
      )}

      <div className="public-check__warning">
        <span className="scope-note__icon" aria-hidden="true">i</span>
        <p><strong>Preliminary only:</strong> this check sends no exploit payloads and does not verify vulnerability or safety. Arbitrary public URLs are deliberately disabled.</p>
      </div>
    </section>
  )
}

function ResultPanel({ result }: { result: VersionAssessment }) {
  const isUnknown = result.status === 'UNKNOWN'

  return (
    <section className="results-panel" aria-labelledby="results-heading" aria-live="polite">
      <div className="results-heading">
        <div>
          <p className="eyebrow">Assessment result</p>
          <h2 id="results-heading">
            {result.version ? <>PHP <code>{result.version}</code></> : 'Version could not be assessed'}
          </h2>
          <a className="source-link results-source-link" href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
            Official PHP advisory <span aria-hidden="true">↗</span>
          </a>
        </div>
        <span className={`overall-status overall-status--${result.status.toLowerCase()}`}>
          <StatusMark status={result.status} />
          {statusLabels[result.status]}
        </span>
      </div>

      {isUnknown && <p className="result-notice">{result.summary}</p>}

      <div className="cve-list">
        {result.vulnerabilities.map((vulnerability) => (
          <article className="cve-card" key={vulnerability.cveId}>
            <div className="cve-card__topline">
              <span className="cve-id">{vulnerability.cveId}</span>
              <span className={`cve-status cve-status--${vulnerability.status.toLowerCase()}`}>
                {statusLabels[vulnerability.status]}
              </span>
            </div>
            <h3>{vulnerability.title}</h3>
            <p>{vulnerability.evidence}</p>
            <p className="recommendation"><strong>Recommended next step:</strong> {vulnerability.recommendation}</p>
          </article>
        ))}
      </div>

      <div className="fixed-guidance">
        <div className="fixed-guidance__icon" aria-hidden="true">↗</div>
        <div>
          <h3>First fixed upstream releases</h3>
          <p>
            {PHP_SECURITY_ADVISORY.vulnerabilities[0].fixedReleases
              .map((release) => `${release.branch}: ${release.version}`)
              .join(' · ')}.
            {' '}Vendor packages may include backports; confirm with your distribution or hosting provider.
          </p>
        </div>
      </div>

      <div className="evidence-note">
        <span className="evidence-note__icon" aria-hidden="true">i</span>
        <p><strong>Evidence boundary</strong>{' '}{result.confidenceExplanation} A version match is not a test of the running site and cannot establish whether vendor backports are present.</p>
      </div>
    </section>
  )
}

function App() {
  const [phpVersion, setPhpVersion] = useState('')
  const [result, setResult] = useState<VersionAssessment | null>(null)
  const [inputError, setInputError] = useState('')

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trimmedVersion = phpVersion.trim()

    if (!trimmedVersion) {
      setResult(null)
      setInputError('Enter a PHP version to assess, for example 8.2.34.')
      return
    }

    setInputError('')
    setResult(assessPhpVersion(trimmedVersion))
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="PHP2Shell Guard home">
          <span className="brand-mark" aria-hidden="true"><span /></span>
          <span>PHP2Shell <strong>Guard</strong></span>
        </a>
        <span className="offline-label"><span className="offline-dot" /> Version checks · website check</span>
      </header>

      <main id="top">
        <section className="hero">
          <p className="eyebrow"><span className="eyebrow-line" /> PHP SECURITY ADVISORY</p>
          <h1>Know where your PHP version stands.</h1>
          <p className="hero-copy">
            Compare a PHP version against official fixed releases, or request limited public-header
            evidence from explicitly allowlisted websites.
          </p>

          <div className="assessment-card">
            <form className="version-form" onSubmit={handleSubmit} noValidate>
              <label htmlFor="php-version">PHP version</label>
              <div className="form-controls">
                <div className={`input-wrap${inputError ? ' input-wrap--error' : ''}`}>
                  <span className="input-prefix" aria-hidden="true">PHP</span>
                  <input
                    id="php-version"
                    name="php-version"
                    type="text"
                    inputMode="decimal"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="8.2.34"
                    value={phpVersion}
                    onChange={(event) => {
                      setPhpVersion(event.target.value)
                      if (inputError) setInputError('')
                    }}
                    aria-invalid={Boolean(inputError)}
                    aria-describedby={inputError ? 'version-error version-help' : 'version-help'}
                  />
                </div>
                <button className="submit-button" type="submit">
                  Check PHP version
                  <span aria-hidden="true">→</span>
                </button>
              </div>
              {inputError
                ? <p className="input-error" id="version-error" role="alert">{inputError}</p>
                : null}
              <p className="field-help" id="version-help">Enter a stable version such as 8.2.34. A leading “PHP” is optional.</p>
            </form>
          </div>
        </section>

        {result ? (
          <ResultPanel result={result} />
        ) : (
          <section className="advisory-overview" aria-labelledby="advisory-heading">
            <div className="section-title">
              <div>
                <p className="eyebrow">What this check covers</p>
                <h2 id="advisory-heading">Two CVEs. One upstream version check.</h2>
              </div>
              <a className="source-link" href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
                Official PHP advisory <span aria-hidden="true">↗</span>
              </a>
            </div>
            <div className="advisory-grid">
              {PHP_SECURITY_ADVISORY.vulnerabilities.map((vulnerability) => (
                <article className="advisory-card" key={vulnerability.cveId}>
                  <div className="advisory-card__id">{vulnerability.cveId}</div>
                  <h3>{vulnerability.title}</h3>
                  <p>{vulnerability.shortDescription}</p>
                </article>
              ))}
            </div>
            <div className="fixed-guidance">
              <div className="fixed-guidance__icon" aria-hidden="true">↗</div>
              <div>
                <h3>Upstream fixed releases</h3>
                <p>
                  PHP {PHP_SECURITY_ADVISORY.vulnerabilities[0].fixedReleases.map((release) => release.version).join(' · ')}.
                  {' '}For older or vendor-packaged builds, confirm fixes with your distribution or hosting provider.
                </p>
              </div>
            </div>
          </section>
        )}

        <PublicWebsiteCheck />

        <section className="scope-note" aria-label="Assessment limitations">
          <div className="scope-note__icon" aria-hidden="true">i</div>
          <div>
            <h2>Version assessment is not vulnerability testing</h2>
            <p>
              The version check is offline; the website check makes one HEAD request only to exact allowlisted hosts.
              Neither verifies server packages or vendor backports. A patched-version result is evidence about a
              version string—not proof that an installation is secure.
            </p>
          </div>
        </section>
      </main>

      <footer className="footer">
        <span>PHP2Shell Guard <span aria-hidden="true">·</span> Milestone 2: public-header assessment</span>
        <a href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
          Source verified {PHP_SECURITY_ADVISORY.lastVerified}
        </a>
      </footer>
    </div>
  )
}

export default App
