"""add email verification fields and OTP table

Revision ID: 63c47e15f062
Revises: 959ee6b2cff1
Create Date: 2025-09-17 07:58:51.415294

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '63c47e15f062'
down_revision: Union[str, Sequence[str], None] = '959ee6b2cff1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.add_column("User", sa.Column("is_email_verified", sa.Boolean(), nullable=True))

    # Create new table EmailVerificationOTP
    op.create_table(
        "EmailVerificationOTP",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String()),
        sa.Column("username", sa.String()),
        sa.Column("hashed_password", sa.String()),
        sa.Column("otp_code", sa.String()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("is_used", sa.Boolean()),
        sa.Column("attempts", sa.Integer()),
    )


def downgrade() -> None:
    """Downgrade schema."""
    pass
