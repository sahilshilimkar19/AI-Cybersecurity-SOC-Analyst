/**
 * Approval-flow tests.
 *
 * This is the component where the platform's central promise is kept, so the
 * tests are about friction rather than features: a decision cannot be submitted
 * blank, asking for changes cannot be submitted without a reason, an open gate
 * with an empty plan still reads as work waiting, and the panel says out loud
 * that approving does not execute anything.
 */

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { PendingApproval } from '../api/types'
import { ApprovalPanel } from './ApprovalPanel'
import type { ApprovalPanelProps } from './ApprovalPanel'

const ITEM: PendingApproval = {
  kind: 'recommendation',
  id: 'r1',
  investigation_id: 'inv-1',
  title: 'Enforce account lockout on web-01',
  priority: 'high',
  confidence: null,
  rationale: 'Repeated authentication failures preceded a successful login.',
}

function panel(overrides: Partial<ApprovalPanelProps> = {}) {
  const onDecide = vi.fn()
  const props: ApprovalPanelProps = {
    gateOpen: true,
    items: [ITEM],
    verdict: 'malicious',
    priority: 'urgent',
    confidence: 0.82,
    gaps: [],
    canApprove: true,
    submitting: false,
    error: null,
    onDecide,
    ...overrides,
  }
  render(<ApprovalPanel {...props} />)
  return { onDecide }
}

describe('what the analyst is shown', () => {
  it('shows the verdict, priority, and confidence next to the buttons', () => {
    panel()

    expect(screen.getByText('malicious')).toBeInTheDocument()
    expect(screen.getByText('urgent')).toBeInTheDocument()
    // Confidence is named in words as well as given as a number: "0.82" invites
    // a precision that is not there, "high" is what it means.
    expect(screen.getByText('high', { selector: '.confidence-word' })).toBeInTheDocument()
    expect(screen.getByText(/82%/)).toBeInTheDocument()
  })

  it('states what was not established, next to the decision', () => {
    panel({ gaps: ['CVE research did not complete.'] })

    expect(screen.getByText('What was not established')).toBeInTheDocument()
    expect(screen.getByText('CVE research did not complete.')).toBeInTheDocument()
  })

  it('says plainly that approving does not carry the work out', () => {
    panel()
    expect(screen.getByText(/does not carry it out/i)).toBeInTheDocument()
  })

  it('offers no single default button that invites a rubber stamp', () => {
    panel()
    // Every decision is an equal radio choice; nothing is preselected.
    const options = screen.getAllByRole('radio')
    expect(options).toHaveLength(4)
    expect(options.every((option) => !(option as HTMLInputElement).checked)).toBe(true)
  })
})

describe('what the analyst may do', () => {
  it('refuses to submit without a decision', async () => {
    const { onDecide } = panel()

    await userEvent.click(screen.getByRole('button', { name: /record decision/i }))

    expect(onDecide).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('Choose a decision.')
  })

  it('submits a plain approval without requiring a reason', async () => {
    const { onDecide } = panel()

    await userEvent.click(screen.getByRole('radio', { name: /approve/i }))
    await userEvent.click(screen.getByRole('button', { name: /record decision/i }))

    expect(onDecide).toHaveBeenCalledWith({ decision: 'approve' })
  })

  it.each(['edit', 'reject', 'redirect'] as const)(
    'requires a reason for %s',
    async (decision) => {
      const labels = { edit: /request changes/i, reject: /reject/i, redirect: /send back/i }
      const { onDecide } = panel()

      await userEvent.click(screen.getByRole('radio', { name: labels[decision] }))
      await userEvent.click(screen.getByRole('button', { name: /record decision/i }))

      expect(onDecide).not.toHaveBeenCalled()
      expect(screen.getByRole('alert')).toHaveTextContent(/Say why/)
    },
  )

  it('carries the rationale and the redirect target through', async () => {
    const { onDecide } = panel()

    await userEvent.click(screen.getByRole('radio', { name: /send back/i }))
    await userEvent.type(screen.getByRole('textbox', { name: /rationale/i }), 'Check egress.')
    await userEvent.type(
      screen.getByRole('textbox', { name: /re-examined/i }),
      'outbound connections',
    )
    await userEvent.click(screen.getByRole('button', { name: /record decision/i }))

    expect(onDecide).toHaveBeenCalledWith({
      decision: 'redirect',
      rationale: 'Check egress.',
      target: 'outbound connections',
    })
  })

  it('disables submission while a decision is being recorded', () => {
    panel({ submitting: true })
    expect(screen.getByRole('button', { name: /recording/i })).toBeDisabled()
  })

  it('surfaces the server error rather than swallowing it', () => {
    panel({ error: 'investigation is closed; there is no open approval gate to decide' })
    expect(screen.getByRole('alert')).toHaveTextContent(/no open approval gate/)
  })
})

describe('when there is nothing to approve', () => {
  it('still reports an open gate as work waiting on a person', () => {
    panel({ items: [] })

    expect(screen.getByText(/paused at the gate/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /record decision/i })).toBeInTheDocument()
  })

  it('says nothing is pending when the gate is closed', () => {
    panel({ gateOpen: false })

    expect(screen.getByText(/not waiting on a decision/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /record decision/i })).toBeNull()
  })
})

describe('when the role cannot approve', () => {
  it('offers no decision form and says who can', () => {
    panel({ canApprove: false })

    expect(screen.queryByRole('radio')).toBeNull()
    expect(screen.getByText(/senior analyst or manager/i)).toBeInTheDocument()
  })
})
