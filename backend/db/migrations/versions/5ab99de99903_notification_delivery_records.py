"""notification delivery records

Revision ID: 5ab99de99903
Revises: b658a15c7d1f
Create Date: 2026-08-07 12:51:14.542307

Turns the notifications table into the enforcement point for "no alert without a
human approval" (invariant #1). ``approval_id`` becomes NOT NULL, so a
notification nobody authorized cannot be represented as a row at all — the rule
stops depending on whichever code path happens to do the insert.

``dedupe_key`` is NOT NULL *and* unique, which makes idempotency the database's
job rather than a check-then-act in application code that a retry or a race would
defeat.

**Precondition: the table must be empty.** No dispatcher existed before this
revision, so in every real deployment it is. The migration checks rather than
assumes, and fails with an explanation instead of guessing, because the two ways
of guessing are both wrong here: a server default for ``dedupe_key`` would give
every existing row the same value and break the uniqueness constraint, and
deleting rows to make the migration succeed would destroy exactly the delivery
history an incident review needs. If this fails, the rows it found are
notifications with no verified approval behind them — which is a finding, not an
obstacle, and wants a person rather than a workaround.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5ab99de99903'
down_revision: str | None = 'b658a15c7d1f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _require_empty_table() -> None:
    existing = op.get_bind().execute(sa.text("SELECT count(*) FROM notifications")).scalar_one()
    if existing:
        raise RuntimeError(
            f"notifications holds {existing} row(s), but this revision adds a unique "
            "NOT NULL dedupe_key that cannot be back-filled without either breaking "
            "the constraint or fabricating delivery history. No dispatcher existed "
            "before this revision, so these rows need a human to explain them."
        )


def upgrade() -> None:
    _require_empty_table()
    op.add_column('notifications', sa.Column('dedupe_key', sa.String(length=64), nullable=False))
    op.add_column(
        'notifications',
        sa.Column(
            'priority',
            sa.Enum(
                'low',
                'medium',
                'high',
                'urgent',
                name='triage_priority',
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
    )
    op.add_column('notifications', sa.Column('failure_reason', sa.String(length=500), nullable=True))
    op.alter_column('notifications', 'approval_id', existing_type=sa.UUID(), nullable=False)
    op.create_index(
        op.f('ix_notifications_approval_id'), 'notifications', ['approval_id'], unique=False
    )
    op.create_unique_constraint('uq_notifications_dedupe_key', 'notifications', ['dedupe_key'])


def downgrade() -> None:
    op.drop_constraint('uq_notifications_dedupe_key', 'notifications', type_='unique')
    op.drop_index(op.f('ix_notifications_approval_id'), table_name='notifications')
    op.alter_column('notifications', 'approval_id', existing_type=sa.UUID(), nullable=True)
    op.drop_column('notifications', 'failure_reason')
    op.drop_column('notifications', 'priority')
    op.drop_column('notifications', 'dedupe_key')
