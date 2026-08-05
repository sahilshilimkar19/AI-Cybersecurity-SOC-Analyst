/**
 * The human approval moment.
 *
 * This component is where the platform's central promise is either kept or
 * quietly broken, so it is built to make approving *deliberate* rather than
 * convenient (SAD §13).
 *
 * Four things are load-bearing:
 *
 * - **What is being decided is shown, not summarized away.** Confidence, the
 *   verdict, the pipeline's gaps, and the count of items pending are all on
 *   screen next to the buttons.
 * - **Approve and reject are not styled as a default.** There is no primary
 *   button that the eye and the keyboard both fall onto; a rubber stamp should
 *   take the same effort as a refusal.
 * - **A rationale is required for anything other than a plain approval.** Edit,
 *   reject, and redirect all say "do something different", and an instruction
 *   with no reason attached is one the next person cannot act on.
 * - **The panel states that approving does not execute.** It authorizes work.
 *   Someone still has to do it, and an analyst who believes otherwise will not
 *   go and do it (invariant #2).
 */

import { useState } from 'react'
import type { FormEvent, ReactElement } from 'react'

import type { DecisionType, PendingApproval, TriagePriority, Verdict } from '../api/types'
import { ConfidenceMeter, PriorityBadge, VerdictBadge } from './Indicators'

const DECISIONS: { value: DecisionType; label: string; help: string }[] = [
  {
    value: 'approve',
    label: 'Approve',
    help: 'Accept the findings. The report becomes final. Nothing is executed.',
  },
  {
    value: 'edit',
    label: 'Request changes',
    help: 'Accept the case but ask for changes first. The report stays a draft.',
  },
  { value: 'reject', label: 'Reject', help: 'Record that the findings were not accepted.' },
  {
    value: 'redirect',
    label: 'Send back',
    help: 'Return the investigation for further work, saying what to re-examine.',
  },
]

/** Decisions that mean "do something different", and therefore need a reason. */
const REQUIRES_RATIONALE = new Set<DecisionType>(['edit', 'reject', 'redirect'])

export interface ApprovalPanelProps {
  gateOpen: boolean
  items: PendingApproval[]
  verdict: Verdict | null
  priority: TriagePriority | null
  confidence: number | null
  /** Stages that have neither completed nor been skipped — what was not established. */
  gaps: string[]
  canApprove: boolean
  submitting: boolean
  error: string | null
  onDecide: (input: { decision: DecisionType; rationale?: string; target?: string }) => void
}

export function ApprovalPanel({
  gateOpen,
  items,
  verdict,
  priority,
  confidence,
  gaps,
  canApprove,
  submitting,
  error,
  onDecide,
}: ApprovalPanelProps): ReactElement {
  const [decision, setDecision] = useState<DecisionType | null>(null)
  const [rationale, setRationale] = useState('')
  const [target, setTarget] = useState('')
  const [validation, setValidation] = useState<string | null>(null)

  if (!gateOpen) {
    return (
      <section className="approval-panel approval-closed" aria-labelledby="approval-heading">
        <h2 id="approval-heading">Human approval</h2>
        <p>This investigation is not waiting on a decision.</p>
      </section>
    )
  }

  if (!canApprove) {
    return (
      <section className="approval-panel approval-readonly" aria-labelledby="approval-heading">
        <h2 id="approval-heading">Human approval</h2>
        <p>
          This investigation is waiting on a decision. Your role cannot record one — ask a senior
          analyst or manager.
        </p>
      </section>
    )
  }

  function submit(event: FormEvent): void {
    event.preventDefault()
    if (decision === null) {
      setValidation('Choose a decision.')
      return
    }
    if (REQUIRES_RATIONALE.has(decision) && rationale.trim() === '') {
      setValidation('Say why. An instruction with no reason is one nobody can act on.')
      return
    }
    setValidation(null)
    onDecide({
      decision,
      ...(rationale.trim() === '' ? {} : { rationale: rationale.trim() }),
      ...(target.trim() === '' ? {} : { target: target.trim() }),
    })
  }

  return (
    <section className="approval-panel" aria-labelledby="approval-heading">
      <h2 id="approval-heading">Human approval required</h2>

      <div className="approval-context">
        <VerdictBadge verdict={verdict} />
        <PriorityBadge priority={priority} />
        <ConfidenceMeter confidence={confidence} />
      </div>

      {gaps.length > 0 && (
        <div className="approval-gaps" role="note">
          <h3>What was not established</h3>
          <ul>
            {gaps.map((gap) => (
              <li key={gap}>{gap}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="approval-items">
        <h3>Awaiting your decision ({items.length})</h3>
        {items.length === 0 ? (
          <p>
            Nothing is queued for approval, but the investigation is paused at the gate and will
            not proceed until you decide.
          </p>
        ) : (
          <ul>
            {items.map((item) => (
              <li key={item.id} className={`approval-item kind-${item.kind}`}>
                <span className="item-kind">{item.kind}</span>
                <span className="item-title">{item.title}</span>
                <PriorityBadge priority={item.priority} />
                {item.rationale !== null && <p className="item-rationale">{item.rationale}</p>}
              </li>
            ))}
          </ul>
        )}
      </div>

      <form onSubmit={submit} className="approval-form">
        <fieldset>
          <legend>Your decision</legend>
          {DECISIONS.map((option) => (
            <label key={option.value} className="decision-option">
              <input
                type="radio"
                name="decision"
                value={option.value}
                checked={decision === option.value}
                onChange={() => {
                  setDecision(option.value)
                  setValidation(null)
                }}
              />
              <span className="decision-label">{option.label}</span>
              <span className="decision-help">{option.help}</span>
            </label>
          ))}
        </fieldset>

        <label className="approval-field">
          <span>
            Rationale
            {decision !== null && REQUIRES_RATIONALE.has(decision) ? ' (required)' : ' (optional)'}
          </span>
          <textarea
            value={rationale}
            onChange={(event) => setRationale(event.target.value)}
            rows={3}
          />
        </label>

        {decision === 'redirect' && (
          <label className="approval-field">
            <span>What should be re-examined?</span>
            <input value={target} onChange={(event) => setTarget(event.target.value)} />
          </label>
        )}

        {validation !== null && (
          <p role="alert" className="approval-error">
            {validation}
          </p>
        )}
        {error !== null && (
          <p role="alert" className="approval-error">
            {error}
          </p>
        )}

        <p className="approval-note">
          Recording a decision does not carry it out. Approving authorizes the recommended work; a
          person still has to perform it.
        </p>

        <button type="submit" disabled={submitting}>
          {submitting ? 'Recording…' : 'Record decision'}
        </button>
      </form>
    </section>
  )
}
