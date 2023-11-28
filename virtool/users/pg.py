from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, ForeignKey, Table, CheckConstraint, select, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from virtool.groups.pg import SQLGroup
from virtool.pg.base import Base

user_group_associations = Table(
    "user_group_associations",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE")),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE")),
)


class SQLUser(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    legacy_id: Mapped[str | None] = mapped_column(unique=True)
    active: Mapped[bool] = mapped_column(default=True)
    administrator: Mapped[bool] = mapped_column(default=False)
    b2c_display_name: Mapped[str] = mapped_column(default="")
    b2c_given_name: Mapped[str] = mapped_column(default="")
    b2c_family_name: Mapped[str] = mapped_column(default="")
    b2c_oid: Mapped[str] = mapped_column(default="")
    force_reset: Mapped[bool] = mapped_column(default=False)
    handle: Mapped[str]
    invalidate_sessions: Mapped[bool] = mapped_column(default=False)
    last_password_change: Mapped[datetime]
    password: Mapped[bytes | None]

    groups: Mapped[list[SQLGroup]] = relationship(secondary=user_group_associations)

    primary_group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"))
    primary_group: Mapped[SQLGroup | None] = relationship()
    CheckConstraint(
        primary_group_id.in_(
            select(
                Column(
                    "group_id",
                    Integer(),
                    ForeignKey("groups.id"),
                )
            )
        ),
        name="primary_group_in_groups",
    )

    def __repr__(self):
        params = ", ".join(
            f"{column}='{type(value).__name__ if column == 'last_password_change' else value}'"
            for column, value in self.to_dict().items()
            if column not in ["password"]
        )

        return f"<{self.__class__.__name__}({params})>"
