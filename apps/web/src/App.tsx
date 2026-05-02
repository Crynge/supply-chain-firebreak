import { startTransition, useEffect, useMemo, useState } from 'react'
import './App.css'

type Severity = 'critical' | 'high' | 'medium' | 'low'

type Finding = {
  rule_id: string
  severity: Severity
  workflow: string
  job: string | null
  step: string | null
  title: string
  description: string
  recommendation: string
  evidence: string
}

type WorkflowSummary = {
  path: string
  triggers: string[]
  risk_score: number
  findings: Finding[]
}

type RepoReport = {
  repo_name: string
  root: string
  total_findings: number
  risk_score: number
  severity_counts: Record<Severity, number>
  urgent_fix_queue: string[]
  workflow_summaries: WorkflowSummary[]
  repo_recommendations: string[]
}

const sourceTimeline = [
  {
    date: 'March 26, 2026',
    label: 'GitHub Actions roadmap',
    detail: 'GitHub says attackers are targeting CI/CD automation itself and over-permissioned credentials remain a core failure mode.',
  },
  {
    date: 'April 1, 2026',
    label: 'GitHub supply chain guidance',
    detail: 'GitHub says recent attacks focus on exfiltrating secrets and often start with compromised GitHub Actions workflows.',
  },
  {
    date: 'April 23, 2026',
    label: 'Bitwarden CLI compromise',
    detail: 'Socket reports a CI/CD compromise chain involving a poisoned GitHub Action and stolen package-publish credentials.',
  },
  {
    date: 'April 30, 2026',
    label: 'Lightning PyPI compromise',
    detail: 'Snyk reports malicious `lightning` releases carrying a Bun-based credential stealer in a popular Python package.',
  },
]

async function loadReport(path: string): Promise<RepoReport> {
  const response = await fetch(path)
  if (!response.ok) {
    throw new Error(`Failed to load ${path}`)
  }
  return response.json() as Promise<RepoReport>
}

function severityOrder(severity: Severity): number {
  return ['critical', 'high', 'medium', 'low'].indexOf(severity)
}

function App() {
  const [vulnerableReport, setVulnerableReport] = useState<RepoReport | null>(null)
  const [secureReport, setSecureReport] = useState<RepoReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all')
  const [workflowFocus, setWorkflowFocus] = useState<string | null>(null)

  useEffect(() => {
    async function load() {
      try {
        const [vulnerable, secure] = await Promise.all([
          loadReport('/vulnerable-report.json'),
          loadReport('/secure-report.json'),
        ])
        startTransition(() => {
          setVulnerableReport(vulnerable)
          setSecureReport(secure)
          setWorkflowFocus(vulnerable.workflow_summaries[0]?.path ?? null)
        })
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : 'Failed to load reports.')
      }
    }

    void load()
  }, [])

  const vulnerableFindings = useMemo(() => {
    if (!vulnerableReport) return []
    return vulnerableReport.workflow_summaries
      .flatMap((workflow) => workflow.findings)
      .sort((left, right) => severityOrder(left.severity) - severityOrder(right.severity))
  }, [vulnerableReport])

  const filteredFindings = useMemo(() => {
    if (severityFilter === 'all') return vulnerableFindings
    return vulnerableFindings.filter((finding) => finding.severity === severityFilter)
  }, [severityFilter, vulnerableFindings])

  const focusedWorkflow = useMemo(() => {
    return vulnerableReport?.workflow_summaries.find((workflow) => workflow.path === workflowFocus) ?? null
  }, [vulnerableReport, workflowFocus])

  if (error) {
    return (
      <main className="shell shell--centered">
        <p className="eyebrow">Supply Chain Firebreak</p>
        <h1>Report load failed</h1>
        <p>{error}</p>
      </main>
    )
  }

  if (!vulnerableReport || !secureReport) {
    return (
      <main className="shell shell--centered">
        <div className="loading-radar"></div>
        <p className="eyebrow">Generating control view</p>
      </main>
    )
  }

  return (
    <main className="shell">
      <section className="hero-card">
        <div className="hero-card__copy">
          <p className="eyebrow">Late-April 2026 coding pressure point</p>
          <h1>CI/CD supply-chain compromise is the issue that can silently turn healthy code into malicious releases.</h1>
          <p className="body-copy">
            Firebreak turns recent attack patterns into repo-native scanning: untrusted workflow execution, floating
            actions, self-hosted runner exposure, long-lived publish tokens, and missing OIDC trusted publishing.
          </p>
          <div className="hero-card__stats">
            <article>
              <span>Vulnerable fixture</span>
              <strong>{vulnerableReport.risk_score}/100</strong>
            </article>
            <article>
              <span>Hardened fixture</span>
              <strong>{secureReport.risk_score}/100</strong>
            </article>
            <article>
              <span>Critical delta</span>
              <strong>{vulnerableReport.severity_counts.critical - secureReport.severity_counts.critical}</strong>
            </article>
          </div>
        </div>
        <div className="timeline-card">
          {sourceTimeline.map((item) => (
            <article key={item.date + item.label} className="timeline-card__item">
              <span>{item.date}</span>
              <strong>{item.label}</strong>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="compare-grid">
        {[vulnerableReport, secureReport].map((report) => (
          <article key={report.repo_name} className="compare-card">
            <div className="compare-card__header">
              <div>
                <p className="eyebrow">{report.repo_name === 'vulnerable-repo' ? 'Attack path' : 'Hardened path'}</p>
                <h2>{report.repo_name}</h2>
              </div>
              <span className={`score-pill score-pill--${report.risk_score > 60 ? 'hot' : 'cool'}`}>{report.risk_score}/100</span>
            </div>
            <div className="severity-grid">
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => (
                <div key={severity} className="severity-box">
                  <span>{severity}</span>
                  <strong>{report.severity_counts[severity]}</strong>
                </div>
              ))}
            </div>
            <ul className="queue-list">
              {report.urgent_fix_queue.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
        ))}
      </section>

      <section className="main-grid">
        <article className="panel">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Workflow attack map</p>
              <h2>Risky execution lanes</h2>
            </div>
            <span className="tag">real scanner output</span>
          </div>
          <div className="workflow-list">
            {vulnerableReport.workflow_summaries.map((workflow) => (
              <button
                key={workflow.path}
                type="button"
                className={`workflow-card${workflow.path === workflowFocus ? ' workflow-card--active' : ''}`}
                onClick={() => setWorkflowFocus(workflow.path)}
              >
                <div className="workflow-card__topline">
                  <strong>{workflow.path}</strong>
                  <span>{workflow.risk_score}/100</span>
                </div>
                <p>{workflow.triggers.join(', ') || 'manual'}</p>
                <small>{workflow.findings.length} findings</small>
              </button>
            ))}
          </div>
          {focusedWorkflow ? (
            <div className="workflow-focus">
              <h3>{focusedWorkflow.path}</h3>
              <p>Triggers: {focusedWorkflow.triggers.join(', ')}</p>
              <ul>
                {focusedWorkflow.findings.map((finding) => (
                  <li key={`${finding.rule_id}-${finding.title}`}>
                    <span className={`severity-pill severity-pill--${finding.severity}`}>{finding.severity}</span>
                    <div>
                      <strong>{finding.title}</strong>
                      <p>{finding.description}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </article>

        <article className="panel">
          <div className="panel__header">
            <div>
              <p className="eyebrow">Priority desk</p>
              <h2>Findings board</h2>
            </div>
            <div className="filter-row">
              {(['all', 'critical', 'high', 'medium', 'low'] as const).map((severity) => (
                <button
                  key={severity}
                  type="button"
                  className={`filter-chip${severityFilter === severity ? ' filter-chip--active' : ''}`}
                  onClick={() => setSeverityFilter(severity)}
                >
                  {severity}
                </button>
              ))}
            </div>
          </div>
          <div className="finding-list">
            {filteredFindings.map((finding) => (
              <article key={`${finding.workflow}-${finding.rule_id}-${finding.title}`} className="finding-card">
                <div className="finding-card__header">
                  <span className={`severity-pill severity-pill--${finding.severity}`}>{finding.severity}</span>
                  <span>{finding.workflow}</span>
                </div>
                <h3>{finding.title}</h3>
                <p>{finding.description}</p>
                <div className="finding-card__evidence">
                  <strong>Evidence</strong>
                  <p>{finding.evidence}</p>
                </div>
                <div className="finding-card__recommendation">
                  <strong>Fix</strong>
                  <p>{finding.recommendation}</p>
                </div>
              </article>
            ))}
          </div>
        </article>
      </section>

      <section className="recommendation-panel">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Firebreak response model</p>
            <h2>Repo-level remediation priorities</h2>
          </div>
        </div>
        <div className="recommendation-grid">
          {vulnerableReport.repo_recommendations.map((item) => (
            <article key={item} className="recommendation-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  )
}

export default App
