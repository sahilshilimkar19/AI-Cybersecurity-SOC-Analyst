/**
 * Where an investigation has got to.
 *
 * Three states, not two. A stage is done, deliberately skipped, or outstanding —
 * and collapsing "skipped" into either of the others would tell an analyst
 * something false. CVE research on a benign verdict was correctly not performed;
 * shown as outstanding it looks stuck, and shown as complete it claims an estate
 * was checked when it was not.
 */

import type { ReactElement } from 'react'

import type { PipelineStage } from '../api/types'

function stageState(stage: PipelineStage): { label: string; className: string } {
  if (stage.complete) return { label: 'done', className: 'stage-complete' }
  if (stage.skipped) return { label: 'not required', className: 'stage-skipped' }
  return { label: 'pending', className: 'stage-pending' }
}

export function PipelineProgress({ stages }: { stages: PipelineStage[] }): ReactElement {
  return (
    <ol className="pipeline" aria-label="Investigation pipeline">
      {stages.map((stage) => {
        const state = stageState(stage)
        return (
          <li key={stage.name} className={`pipeline-stage ${state.className}`}>
            <span className="stage-name">{stage.label}</span>
            <span className="stage-state">{state.label}</span>
            {stage.detail !== null && <span className="stage-detail">{stage.detail}</span>}
          </li>
        )
      })}
    </ol>
  )
}
