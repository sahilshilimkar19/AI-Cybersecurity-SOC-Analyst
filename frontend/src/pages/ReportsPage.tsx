/**
 * Report review, versions, and export (SAD §13).
 *
 * The body is rendered as text, not as HTML. A report quotes raw log lines, and
 * turning Markdown into markup in the browser is precisely how a quoted log line
 * becomes an executing script on the console of the person investigating it. The
 * cost is plainer typography; the alternative is stored XSS in the one screen an
 * analyst reads most carefully.
 *
 * Export writes the same text to a file the browser assembles locally, so
 * exporting cannot become a second, unaudited way to move a report somewhere.
 *
 * Version history is offered rather than only the latest, because the document a
 * decision rested on has to stay readable after the next regeneration.
 */

import { useState } from 'react'
import type { ReactElement } from 'react'
import { useParams } from 'react-router'

import type { ApiClient } from '../api/client'
import { useReport, useReportHistory } from '../api/queries'
import { CitationList } from '../components/Indicators'
import { DocumentText } from '../components/SafeLink'
import { Empty, Failed, Loading } from '../components/States'

/** Assemble the export locally; nothing leaves the browser to produce it. */
export function downloadText(filename: string, contents: string): void {
  const blob = new Blob([contents], { type: 'text/markdown;charset=utf-8' })
  const href = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = href
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(href)
}

export function ReportsPage({ client }: { client: ApiClient }): ReactElement {
  const { investigationId = '' } = useParams<{ investigationId: string }>()
  const [version, setVersion] = useState<number | undefined>(undefined)
  const report = useReport(client, investigationId, version)
  const history = useReportHistory(client, investigationId)

  return (
    <div className="page page-report">
      <h1>Incident report</h1>

      {history.data !== undefined && history.data.versions.length > 1 && (
        <nav className="report-versions" aria-label="Report versions">
          <span>Versions:</span>
          {history.data.versions.map((entry) => (
            <button
              key={entry.id}
              type="button"
              aria-pressed={version === entry.version}
              className={version === entry.version ? 'filter filter-active' : 'filter'}
              onClick={() => setVersion(entry.version)}
            >
              v{entry.version} ({entry.status})
            </button>
          ))}
          <button type="button" className="filter" onClick={() => setVersion(undefined)}>
            Latest
          </button>
        </nav>
      )}

      {report.isLoading && <Loading what="the report" />}
      {report.isError && (
        <Empty>
          No report has been generated for this investigation yet. The reporter runs after threat
          detection.
        </Empty>
      )}
      {history.isError && <Failed what="the version history" error={history.error} />}

      {report.data !== undefined && (
        <article className="report">
          <header className="report-header">
            <span className={`badge report-${report.data.status}`}>{report.data.status}</span>
            <span className="version">v{report.data.version}</span>
            <span className="report-date">
              {new Date(report.data.created_at).toLocaleString()}
            </span>
            <button
              type="button"
              onClick={() =>
                downloadText(
                  `investigation-${investigationId}-report-v${report.data.version}.md`,
                  `${report.data.executive_summary}\n\n${report.data.technical_body}`,
                )
              }
            >
              Export
            </button>
          </header>

          {report.data.status === 'draft' && (
            <p role="note" className="state state-warning">
              This report is a draft. It becomes final only when a person approves the
              investigation.
            </p>
          )}

          <section aria-labelledby="exec-heading">
            <h2 id="exec-heading">Executive summary</h2>
            <DocumentText>{report.data.executive_summary}</DocumentText>
          </section>

          <section aria-labelledby="technical-heading">
            <h2 id="technical-heading">Technical detail</h2>
            <DocumentText>{report.data.technical_body}</DocumentText>
          </section>

          <section aria-labelledby="references-heading">
            <h2 id="references-heading">References</h2>
            <CitationList
              citations={report.data.citations}
              emptyMessage="This report cites no external source."
            />
          </section>
        </article>
      )}
    </div>
  )
}
