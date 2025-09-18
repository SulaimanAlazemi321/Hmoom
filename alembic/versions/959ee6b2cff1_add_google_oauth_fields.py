from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# Alembic identifiers
revision = "959ee6b2cff1"
down_revision = "bce7fca3dec4"
branch_labels = None
depends_on = None

TABLE = "User"  # <-- your actual __tablename__

def upgrade():
    bind = op.get_bind()
    insp = inspect(bind)

    # Add columns safely (no-ops if they already exist)
    existing_cols = {c["name"] for c in insp.get_columns(TABLE)}
    with op.batch_alter_table(TABLE) as b:
        if "google_id" not in existing_cols:
            b.add_column(sa.Column("google_id", sa.String(), nullable=True))
        if "email" not in existing_cols:
            b.add_column(sa.Column("email", sa.String(), nullable=True))
        if "full_name" not in existing_cols:
            b.add_column(sa.Column("full_name", sa.String(), nullable=True))
        if "avatar_url" not in existing_cols:
            b.add_column(sa.Column("avatar_url", sa.String(), nullable=True))

    # Create UNIQUE INDEXes (SQLite-friendly) instead of unique constraints
    existing_idx = {i["name"] for i in insp.get_indexes(TABLE)}
    if "ux_user_google_id" not in existing_idx:
        op.create_index("ux_user_google_id", TABLE, ["google_id"], unique=True)
    if "ux_user_email" not in existing_idx:
        op.create_index("ux_user_email", TABLE, ["email"], unique=True)

def downgrade():
    # Drop indexes first
    op.drop_index("ux_user_email", table_name=TABLE)
    op.drop_index("ux_user_google_id", table_name=TABLE)

    # Drop columns
    with op.batch_alter_table(TABLE) as b:
        b.drop_column("avatar_url")
        b.drop_column("full_name")
        b.drop_column("email")
        b.drop_column("google_id")
