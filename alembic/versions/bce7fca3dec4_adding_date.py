"""adding date"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# --- REQUIRED HEADERS ---
revision = "bce7fca3dec4"
down_revision = "c96f31fd95f5"
branch_labels = None
depends_on = None
# ------------------------

def upgrade():
    bind = op.get_bind()
    insp = inspect(bind)
    cols = {c["name"] for c in insp.get_columns("reflection")}
    if "date" not in cols:
        op.add_column("reflection", sa.Column("date", sa.String(), nullable=True))

def downgrade():
    bind = op.get_bind()
    insp = inspect(bind)
    cols = {c["name"] for c in insp.get_columns("reflection")}
    if "date" in cols:
        op.drop_column("reflection", "date")
