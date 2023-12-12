from __future__ import annotations

from datetime import datetime
from typing import List

from sqlalchemy import (
    Boolean,
    Index,
)
from sqlalchemy import Table, Column, ForeignKey
from sqlalchemy.ext.associationproxy import AssociationProxy
from sqlalchemy.orm import Mapped, mapped_column, relationship

from virtool.groups.pg import SQLGroup
from virtool.pg.base import Base


class UserGroup(Base):
    __tablename__ = "user_group"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[int] = mapped_column(
        ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )

    is_primary: Mapped[bool] = mapped_column(default=False)

    group: Mapped["SQLGroup"] = relationship(lazy="joined")
    user: Mapped["SQLUser"] = relationship(back_populates="user_group_associations")

    Index(
        "primary_group_unique",
        is_primary,
        user_id,
        unique=True,
        postgresql_where=(is_primary == True),
    ),


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

    user_group_associations: Mapped[List[UserGroup]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="joined"
    )

    groups: AssociationProxy[List[SQLGroup]] = AssociationProxy(
        "user_group_associations",
        "group",
        creator=lambda group: UserGroup(group=group),
    )

    primary_group_association: Mapped[UserGroup] = relationship(
        back_populates="user",
        lazy="joined",
        primaryjoin="and_(user_group.c.user_id == SQLUser.id, user_group.c.is_primary == True)",
        viewonly=True,
    )

    primary_group: AssociationProxy[SQLGroup] = AssociationProxy(
        "primary_group_association",
        "group",
    )

    def to_dict(self):
        base_dict = super().to_dict()
        base_dict["groups"] = self.groups
        base_dict["primary_group"] = self.primary_group
        return base_dict

    def __repr__(self):
        params = ", ".join(
            f"{column}='{type(value).__name__ if column == 'last_password_change' else value}'"
            for column, value in self.to_dict().items()
            if column not in ["password"]
        )

        return f"<{self.__class__.__name__}({params})>"
