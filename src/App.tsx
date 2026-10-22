import {
  useState,
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
  type KeyboardEvent,
} from 'react'
import { assessPhpVersion, type AssessmentStatus, type VersionAssessment } from './assessment'
import { assessmentStatusLabels } from './assessment-labels'
import { PHP_SECURITY_ADVISORY } from './data/advisories'
import {
  analyzeDiagnosticReport,
  MAX_DIAGNOSTIC_REPORT_BYTES,
  type DiagnosticAnalysis,
} from './diagnostic'
import phpDiagnosticSource from '../tools/php-diagnostic.php?raw'
import './App.css'

const tabs = [
  { id: 'version', label: 'PHP Version' },
  { id: 'website', label: 'Website Check' },
  { id: 'diagnostic', label: 'Server Diagnostic' },
] as const

type ToolTab = (typeof tabs)[number]['id']

interface PublicScanResult {
  status: 'ASSESSED' | 'INCONCLUSIVE'
  phpVersion: string | null
  summary: string
  evidence: string
  httpStatus: number
  versionAssessment: VersionAssessment | null
}

const vulnerabilityKeys = ['cveId', 'title', 'status', 'evidence', 'recommendation']

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

function isAssessmentStatus(value: unknown): value is AssessmentStatus {
  return value === 'POTENTIALLY_AFFECTED'
    || value === 'UPSTREAM_PATCHED_VERSION'
    || value === 'LEGACY_UNVERIFIED'
    || value === 'UNKNOWN'
}

function isVersionAssessment(value: unknown): value is VersionAssessment {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const assessment = value as Record<string, unknown>
  if (
    !hasExactKeys(assessment, [
      'input',
      'version',
      'status',
      'summary',
      'recommendation',
      'confidenceExplanation',
      'vulnerabilities',
    ])
    || typeof assessment.input !== 'string'
    || assessment.input.length > 128
    || !(typeof assessment.version === 'string' || assessment.version === null)
    || (typeof assessment.version === 'string' && assessment.version.length > 32)
    || !isAssessmentStatus(assessment.status)
    || typeof assessment.summary !== 'string'
    || typeof assessment.recommendation !== 'string'
    || typeof assessment.confidenceExplanation !== 'string'
    || !Array.isArray(assessment.vulnerabilities)
    || assessment.vulnerabilities.length !== PHP_SECURITY_ADVISORY.vulnerabilities.length
  ) {
    return false
  }

  return assessment.vulnerabilities.every((entry: unknown, index: number) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return false
    const vulnerability = entry as Record<string, unknown>
    return hasExactKeys(vulnerability, vulnerabilityKeys)
      && vulnerability.cveId === PHP_SECURITY_ADVISORY.vulnerabilities[index]?.cveId
      && typeof vulnerability.title === 'string'
      && isAssessmentStatus(vulnerability.status)
      && typeof vulnerability.evidence === 'string'
      && typeof vulnerability.recommendation === 'string'
  })
}

function isPublicScanResult(value: unknown): value is PublicScanResult {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const result = value as Record<string, unknown>
  return hasExactKeys(result, [
    'status',
    'phpVersion',
    'summary',
    'evidence',
    'httpStatus',
    'versionAssessment',
  ])
    && (result.status === 'ASSESSED' || result.status === 'INCONCLUSIVE')
    && (typeof result.phpVersion === 'string' || result.phpVersion === null)
    && typeof result.summary === 'string'
    && typeof result.evidence === 'string'
    && typeof result.httpStatus === 'number'
    && Number.isInteger(result.httpStatus)
    && result.httpStatus >= 100
    && result.httpStatus <= 599
    && (result.versionAssessment === null || isVersionAssessment(result.versionAssessment))
}

function StatusMark({ status }: { status: AssessmentStatus }) {
  const symbol = status === 'UPSTREAM_PATCHED_VERSION'
    ? '✓'
    : status === 'POTENTIALLY_AFFECTED' ? '!' : '?'

  return (
    <span className={`status-mark status-mark--${status.toLowerCase()}`} aria-hidden="true">
      {symbol}
    </span>
  )
}

function AssessmentResult({
  assessment,
  source,
  description,
}: {
  assessment: VersionAssessment
  source: string
  description: string
}) {
  const headingId = `result-${source.toLowerCase().replaceAll(' ', '-')}-heading`

  return (
    <section className="result-panel" aria-live="polite" aria-labelledby={headingId}>
      <div className="result-panel__header">
        <div>
          <p className="eyebrow">Assessment result · {source}</p>
          <h3 id={headingId}>
            {assessment.version ? <>PHP <code>{assessment.version}</code></> : 'Version could not be assessed'}
          </h3>
          <p className="result-panel__description">{description}</p>
        </div>
        <span className={`status-pill status-pill--${assessment.status.toLowerCase()}`}>
          <StatusMark status={assessment.status} />
          {assessmentStatusLabels[assessment.status]}
        </span>
      </div>

      {assessment.status === 'UNKNOWN' && <p className="result-notice">{assessment.summary}</p>}

      <div className="cve-list">
        {assessment.vulnerabilities.map((vulnerability) => (
          <article className="cve-card" key={vulnerability.cveId}>
            <div className="cve-card__topline">
              <span className="cve-id">{vulnerability.cveId}</span>
              <span className={`cve-status cve-status--${vulnerability.status.toLowerCase()}`}>
                <StatusMark status={vulnerability.status} />
                {assessmentStatusLabels[vulnerability.status]}
              </span>
            </div>
            <h4>{vulnerability.title}</h4>
            <p>{vulnerability.evidence}</p>
            <p className="recommendation">
              <strong>Recommended next step</strong>
              {vulnerability.recommendation}
            </p>
          </article>
        ))}
      </div>

      <div className="result-panel__footer">
        <p className="evidence-copy">{assessment.confidenceExplanation}</p>
        <a className="text-link" href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
          Read the official PHP advisory <span aria-hidden="true">↗</span>
        </a>
      </div>
    </section>
  )
}

function VersionChecker() {
  const [phpVersion, setPhpVersion] = useState('')
  const [result, setResult] = useState<VersionAssessment | null>(null)
  const [error, setError] = useState('')

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const input = phpVersion.trim()
    if (!input) {
      setResult(null)
      setError('Enter a PHP version, for example 8.2.34.')
      return
    }
    setError('')
    setResult(assessPhpVersion(input))
  }

  return (
    <section className="tool-panel" aria-labelledby="version-tool-heading">
      <div className="tool-panel__intro">
        <p className="eyebrow">Offline version assessment</p>
        <h2 id="version-tool-heading">Check a PHP version</h2>
        <p>Compare a stable PHP version with the first fixed upstream release listed for its branch.</p>
      </div>
      <form className="tool-form" onSubmit={handleSubmit} noValidate>
        <label htmlFor="php-version">PHP version</label>
        <div className="form-controls">
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
              if (error) setError('')
            }}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? 'version-error version-help' : 'version-help'}
          />
          <button className="primary-button" type="submit">Check version</button>
        </div>
        {error && <p className="field-error" id="version-error" role="alert">{error}</p>}
        <p className="field-help" id="version-help">
          Use a stable <code>major.minor.patch</code> version, such as 8.2.34. An optional “PHP” prefix is accepted.
        </p>
      </form>

      {result ? (
        <AssessmentResult
          assessment={result}
          source="manual version"
          description="Assessment based on the version string you entered."
        />
      ) : (
        <div className="fixed-guidance">
          <h3>First fixed upstream releases</h3>
          <ul>
            {PHP_SECURITY_ADVISORY.vulnerabilities[0].fixedReleases.map((release) => (
              <li key={release.branch}><span>PHP {release.branch}</span><code>{release.version}</code></li>
            ))}
          </ul>
          <p>Vendor packages may contain backported fixes. Confirm package-specific status with your vendor.</p>
        </div>
      )}
    </section>
  )
}

function WebsiteChecker() {
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
          ? payload.error.slice(0, 256)
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

  const versionAssessment = result?.versionAssessment ?? null

  return (
    <section className="tool-panel" aria-labelledby="website-tool-heading">
      <div className="tool-panel__intro">
        <p className="eyebrow">Allowlisted hosts only</p>
        <h2 id="website-tool-heading">Check public response headers</h2>
        <p>
          This preliminary check makes one read-only HEAD request to a configured developer-controlled hostname.
          Arbitrary public targets are not enabled.
        </p>
      </div>

      <form className="tool-form" onSubmit={handleSubmit} noValidate>
        <label htmlFor="website-url">Website URL</label>
        <div className="form-controls">
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
          <button className="primary-button" type="submit" disabled={isLoading}>
            {isLoading && <span className="loading-spinner" aria-hidden="true" />}
            {isLoading ? 'Checking…' : 'Check website'}
          </button>
        </div>
        {error && <p className="field-error" id="website-error" role="alert">{error}</p>}
        <p className="field-help" id="website-help">
          HTTPS on port 443 only. The server-side hostname allowlist remains authoritative.
        </p>
      </form>

      {isLoading && <p className="loading-message" role="status">Checking the configured website headers…</p>}
      {result && (
        <div className="scan-result" aria-live="polite">
          <div className="scan-result__summary">
            <div>
              <p className="eyebrow">Preliminary result · HTTP {result.httpStatus}</p>
              <h3>{result.phpVersion ? <>PHP <code>{result.phpVersion}</code></> : 'No version evidence'}</h3>
              <p>{result.summary}</p>
            </div>
            <span className={`status-pill status-pill--${result.status.toLowerCase()}`}>
              {result.status === 'ASSESSED' ? 'Version evidence found' : 'Inconclusive'}
            </span>
          </div>
          {versionAssessment && (
            <AssessmentResult
              assessment={versionAssessment}
              source="public response header"
              description="A response header disclosed this version; headers can be spoofed."
            />
          )}
          {!versionAssessment && <p className="result-notice">{result.evidence}</p>}
          <p className="limitation-note">
            Headers do not prove the actual runtime or package patch status. Vendor patches may be backported.
            This is not exploit testing and does not confirm a vulnerability.
          </p>
          <a className="text-link" href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
            Read the official PHP advisory <span aria-hidden="true">↗</span>
          </a>
        </div>
      )}
    </section>
  )
}

function ServerDiagnostic() {
  const [analysis, setAnalysis] = useState<DiagnosticAnalysis | null>(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const [copyStatus, setCopyStatus] = useState('')

  function downloadScript() {
    const file = new Blob([phpDiagnosticSource], { type: 'text/plain;charset=utf-8' })
    const objectUrl = URL.createObjectURL(file)
    const link = document.createElement('a')
    link.href = objectUrl
    link.download = 'php-diagnostic.php'
    document.body.append(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000)
  }

  async function copyCommand() {
    try {
      await navigator.clipboard.writeText('php php-diagnostic.php > php-report.json')
      setCopyStatus('Command copied.')
    } catch {
      setCopyStatus('Copy was unavailable. Select and copy the command above.')
    }
  }

  async function readReport(file: File | undefined, input?: HTMLInputElement) {
    if (!file) return
    setAnalysis(null)
    setError('')
    setCopyStatus('')
    if (file.size > MAX_DIAGNOSTIC_REPORT_BYTES) {
      setError(`Choose a JSON report no larger than ${MAX_DIAGNOSTIC_REPORT_BYTES / 1024} KB.`)
      if (input) input.value = ''
      return
    }

    setIsLoading(true)
    try {
      setAnalysis(analyzeDiagnosticReport(await file.text()))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The diagnostic report could not be read.')
      if (input) input.value = ''
    } finally {
      setIsLoading(false)
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    void readReport(event.currentTarget.files?.[0], event.currentTarget)
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setIsDragging(false)
    void readReport(event.dataTransfer.files[0])
  }

  return (
    <section className="tool-panel" aria-labelledby="diagnostic-tool-heading">
      <div className="tool-panel__intro">
        <p className="eyebrow">Local · read-only · no upload</p>
        <h2 id="diagnostic-tool-heading">Inspect the PHP CLI runtime</h2>
        <p>Run a small script on infrastructure you control, then assess its JSON report in this browser.</p>
      </div>

      <ol className="diagnostic-steps">
        <li>
          <div>
            <h3>Download and review the script</h3>
            <p>It reports only the PHP version, SAPI, OS family, and UTC timestamp.</p>
            <button className="secondary-button" type="button" onClick={downloadScript}>Download PHP diagnostic</button>
          </div>
        </li>
        <li>
          <div>
            <h3>Run it with PHP CLI</h3>
            <p>Place the script in your chosen working directory and run:</p>
            <code className="diagnostic-command">php php-diagnostic.php &gt; php-report.json</code>
            <button className="copy-button" type="button" onClick={() => void copyCommand()}>Copy command</button>
            {copyStatus && <span className="copy-status" role="status">{copyStatus}</span>}
          </div>
        </li>
      </ol>

      <div
        className={`file-drop${isDragging ? ' file-drop--active' : ''}`}
        onDragOver={(event) => {
          event.preventDefault()
          setIsDragging(true)
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
      >
        <label htmlFor="diagnostic-file">Import the JSON report</label>
        <p>Drop a file here or choose it from your device. Maximum size: {MAX_DIAGNOSTIC_REPORT_BYTES / 1024} KB.</p>
        <input
          id="diagnostic-file"
          name="diagnostic-file"
          type="file"
          accept=".json,application/json"
          onChange={handleFileChange}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? 'diagnostic-error diagnostic-help' : 'diagnostic-help'}
          disabled={isLoading}
        />
        {error && <p className="field-error" id="diagnostic-error" role="alert">{error}</p>}
        {isLoading && <p className="loading-message" role="status">Validating report locally…</p>}
        <p className="field-help" id="diagnostic-help">
          The browser reads the selected file locally. Its contents are not sent to the backend or saved by the app.
        </p>
      </div>

      {analysis && (
        <section className="diagnostic-result" aria-live="polite" aria-labelledby="diagnostic-result-heading">
          <div className="diagnostic-runtime">
            <p className="eyebrow">Local diagnostic evidence · unauthenticated report</p>
            <h3 id="diagnostic-result-heading">PHP <code>{analysis.report.phpVersion}</code> · CLI</h3>
            <dl>
              <div><dt>Runtime</dt><dd>CLI ({analysis.report.sapi})</dd></div>
              <div><dt>Operating system</dt><dd>{analysis.report.osFamily}</dd></div>
              <div>
                <dt>Diagnostic time (UTC)</dt>
                <dd><time dateTime={analysis.report.diagnosticTimestamp}>{analysis.report.diagnosticTimestamp}</time></dd>
              </div>
            </dl>
          </div>
          <AssessmentResult
            assessment={analysis.assessment}
            source="local CLI diagnostic"
            description="Assessment of the PHP version in this user-provided report."
          />
          <p className="limitation-note limitation-note--prominent">
            <strong>CLI is not necessarily web PHP.</strong> The CLI runtime may differ from the PHP version serving
            web traffic. Reports are user-provided and unauthenticated; backports are not verified. This result
            does not prove a vulnerability or establish that a system is secure.
          </p>
        </section>
      )}

      <p className="tool-disclaimer">
        The script is not a web endpoint. It makes no network requests, executes no shell commands, and modifies no files.
      </p>
    </section>
  )
}

function AppHeader() {
  return (
    <header className="site-header">
      <a className="brand" href="#top" aria-label="PHP2Shell Guard home">
        <span className="brand-mark" aria-hidden="true">P</span>
        <span>PHP2Shell <strong>Guard</strong></span>
      </a>
      <a className="header-link" href="https://github.com/Anwar0904/php2shell-guard" target="_blank" rel="noreferrer">
        GitHub <span aria-hidden="true">↗</span>
      </a>
    </header>
  )
}

function AppFooter() {
  return (
    <footer className="site-footer">
      <div>
        <strong>PHP2Shell Guard</strong>
        <p>PHP security advisory evidence, with clear limits and next steps.</p>
      </div>
      <div className="site-footer__links">
        <a href="https://github.com/Anwar0904/php2shell-guard" target="_blank" rel="noreferrer">GitHub</a>
        <a href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">Official PHP advisory</a>
      </div>
      <p className="site-footer__note">
        Version and header evidence do not verify a web runtime, vendor backport, or system security.
      </p>
    </footer>
  )
}

function App() {
  const [activeTab, setActiveTab] = useState<ToolTab>('version')

  function handleTabKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const currentIndex = tabs.findIndex(({ id }) => id === activeTab)
    let nextIndex: number | undefined
    if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length
    if (event.key === 'ArrowLeft') nextIndex = (currentIndex + tabs.length - 1) % tabs.length
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = tabs.length - 1
    if (nextIndex === undefined) return

    event.preventDefault()
    const nextTab = tabs[nextIndex]
    if (nextTab) {
      setActiveTab(nextTab.id)
      document.getElementById(`tool-tab-${nextTab.id}`)?.focus()
    }
  }

  return (
    <div className="app-shell" id="top">
      <AppHeader />
      <main>
        <section className="hero" aria-labelledby="page-heading">
          <p className="eyebrow">PHP SECURITY ADVISORY CHECKS</p>
          <h1 id="page-heading">Know where your PHP stands.</h1>
          <p>
            Check PHP version evidence against official security advisories. Simple results, clear next steps.
          </p>
          <div className="hero__note">
            <span aria-hidden="true">i</span>
            <p>These checks provide evidence, not proof that a website is secure or vulnerable.</p>
          </div>
        </section>

        <section className="tools" aria-label="PHP assessment tools">
          <div className="tool-tabs" role="tablist" aria-label="Choose an assessment tool" onKeyDown={handleTabKeyDown}>
            {tabs.map(({ id, label }) => (
              <button
                key={id}
                id={`tool-tab-${id}`}
                type="button"
                role="tab"
                aria-selected={activeTab === id}
                aria-controls={`tool-panel-${id}`}
                tabIndex={activeTab === id ? 0 : -1}
                onClick={() => setActiveTab(id)}
              >
                {label}
              </button>
            ))}
          </div>
          <div id="tool-panel-version" role="tabpanel" aria-labelledby="tool-tab-version" hidden={activeTab !== 'version'} tabIndex={0}>
            <VersionChecker />
          </div>
          <div id="tool-panel-website" role="tabpanel" aria-labelledby="tool-tab-website" hidden={activeTab !== 'website'} tabIndex={0}>
            <WebsiteChecker />
          </div>
          <div id="tool-panel-diagnostic" role="tabpanel" aria-labelledby="tool-tab-diagnostic" hidden={activeTab !== 'diagnostic'} tabIndex={0}>
            <ServerDiagnostic />
          </div>
        </section>

        <section className="advisory-reference" aria-labelledby="advisory-heading">
          <div>
            <p className="eyebrow">Current coverage</p>
            <h2 id="advisory-heading">Two CVEs, using official upstream release data.</h2>
          </div>
          <div className="advisory-reference__cves">
            {PHP_SECURITY_ADVISORY.vulnerabilities.map(({ cveId, title }) => (
              <div key={cveId}><span>{cveId}</span><p>{title}</p></div>
            ))}
          </div>
          <div className="advisory-reference__footer">
            <p>
              Fixed upstream releases: {PHP_SECURITY_ADVISORY.vulnerabilities[0].fixedReleases
                .map(({ branch, version }) => `${branch}: ${version}`).join(' · ')}.
            </p>
            <a className="text-link" href={PHP_SECURITY_ADVISORY.source} target="_blank" rel="noreferrer">
              Official PHP advisory <span aria-hidden="true">↗</span>
            </a>
          </div>
        </section>
      </main>
      <AppFooter />
    </div>
  )
}

export default App
