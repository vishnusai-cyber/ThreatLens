"""add incident relationship to alerts

Revision ID: daca0e426396
Revises: c34a0d5b77ea
Create Date: 2026-08-13 22:39:32.815355

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# ==========================================================
# Revision identifiers
# ==========================================================

revision: str = "daca0e426396"

down_revision: Union[
    str,
    Sequence[str],
    None
] = "c34a0d5b77ea"

branch_labels: Union[
    str,
    Sequence[str],
    None
] = None

depends_on: Union[
    str,
    Sequence[str],
    None
] = None


# ==========================================================
# UPGRADE
# ==========================================================

def upgrade() -> None:
    """Add incident relationship to alerts."""

    # ------------------------------------------------------
    # Add incident_id column
    # ------------------------------------------------------

    op.add_column(
        "alerts",
        sa.Column(
            "incident_id",
            sa.Integer(),
            nullable=True
        )
    )

    # ------------------------------------------------------
    # Add index
    # ------------------------------------------------------

    op.create_index(
        "ix_alerts_incident_id",
        "alerts",
        ["incident_id"],
        unique=False
    )

    # ------------------------------------------------------
    # Add foreign key
    #
    # alerts.incident_id
    #        ↓
    # incidents.id
    # ------------------------------------------------------

    op.create_foreign_key(
        "fk_alerts_incident_id_incidents",
        "alerts",
        "incidents",
        ["incident_id"],
        ["id"]
    )


# ==========================================================
# DOWNGRADE
# ==========================================================

def downgrade() -> None:
    """Remove incident relationship from alerts."""

    # ------------------------------------------------------
    # Remove foreign key
    # ------------------------------------------------------

    op.drop_constraint(
        "fk_alerts_incident_id_incidents",
        "alerts",
        type_="foreignkey"
    )

    # ------------------------------------------------------
    # Remove index
    # ------------------------------------------------------

    op.drop_index(
        "ix_alerts_incident_id",
        table_name="alerts"
    )

    # ------------------------------------------------------
    # Remove column
    # ------------------------------------------------------

    op.drop_column(
        "alerts",
        "incident_id"
    )