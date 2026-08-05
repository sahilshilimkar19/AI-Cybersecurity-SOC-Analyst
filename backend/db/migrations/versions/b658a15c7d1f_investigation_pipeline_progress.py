"""investigation pipeline progress

Revision ID: b658a15c7d1f
Revises: 9521f5e77c49
Create Date: 2026-08-05 19:59:24.376092

Records which agent stages have run for an investigation, so the dashboard
reports progress from a fact the backend wrote rather than inferring it from
which artifacts happen to exist — an inference that cannot distinguish research
that found nothing from research that never ran.

The column is NOT NULL with a server-side default because investigations already
exist in every deployed environment; adding it without one would fail on the
first row. An investigation that predates this column correctly reports no stage
information rather than claiming stages it has no record of.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b658a15c7d1f'
down_revision: str | None = '9521f5e77c49'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'investigations',
        sa.Column(
            'pipeline',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column('investigations', 'pipeline')
