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

function StatusMark({ status }: { status: AssessmentStatus }) {
  return <span className={`status-mark status-mark--${status.toLowerCase()}`} aria-hidden="true">
    {status === 'UPSTREAM_PATCHED_VERSION' ? '✓' : status === 'POTENTIALLY_AFFECTED' ? '!' : '?'}
  </span>
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
        <span className="offline-label"><span className="offline-dot" /> Offline version check</span>
      </header>

      <main id="top">
        <section className="hero">
          <p className="eyebrow"><span className="eyebrow-line" /> PHP SECURITY ADVISORY</p>
          <h1>Know where your PHP version stands.</h1>
          <p className="hero-copy">
            Check upstream version evidence for two PHP security advisories. No site requests,
            scanning, or exploit testing—just a clear comparison against the official fixed releases.
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

        <section className="scope-note" aria-label="Assessment limitations">
          <div className="scope-note__icon" aria-hidden="true">i</div>
          <div>
            <h2>Version assessment is not vulnerability testing</h2>
            <p>
              This offline check compares the version you enter with published upstream release data.
              It does not inspect a website, verify a server, or account for vendor backports. A patched-version
              result is evidence about the version string only—not proof that an installation is secure.
            </p>
          </div>
        </section>
      </main>

      <footer className="footer">
        <span>PHP2Shell Guard <span aria-hidden="true">·</span> Milestone 1: offline assessment</span>
        <a href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
          Source verified {PHP_SECURITY_ADVISORY.lastVerified}
        </a>
      </footer>
    </div>
  )
}

export default App
