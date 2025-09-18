"""your message

Revision ID: c96f31fd95f5
Revises: 
Create Date: 2025-09-13 09:49:02.417324

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c96f31fd95f5'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("user",sa.Column("email", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("user", "email")
