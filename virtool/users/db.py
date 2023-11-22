"""
Database utilities for managing users.

TODO: Drop legacy group id support when we fully migrate to integer ids.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

import virtool
from virtool.data.errors import ResourceConflictError, ResourceNotFoundError
from virtool.data.topg import compose_legacy_id_expression
from virtool.errors import DatabaseError
from virtool.groups.pg import SQLGroup, merge_group_permissions

ATTACH_PROJECTION = ["_id", "administrator", "handle"]

PROJECTION = [
    "_id",
    "handle",
    "administrator",
    "force_reset",
    "groups",
    "last_password_change",
    "primary_group",
]


@dataclass
class B2CUserAttributes:
    """
    Class to store ID token claims from Azure AD B2C
    """

    display_name: str
    family_name: str
    given_name: str
    oid: str


async def compose_groups_update(
    pg: AsyncEngine, group_ids: list[int | str]
) -> dict[str, list[int | str]]:
    """
    Compose an update dict for updating the list of groups a user is a member of.

    Any legacy string ids will be converted to modern integer ids. A
    ``ResourceConflictError`` will be raised if any of the ``group_ids`` do not exist.

    :param pg: the application Postgres client
    :param group_ids: the group ids to include in update
    :return: an update
    """
    if group_ids is None:
        return {}

    if not group_ids:
        return {"groups": []}

    async with AsyncSession(pg) as session:
        expr = compose_legacy_id_expression(SQLGroup, group_ids)

        result = await session.execute(
            select(SQLGroup.id, SQLGroup.legacy_id).where(expr)
        )

        existing_group_ids = [id_ for row in result.all() for id_ in row]

    non_existent_group_ids = {
        group_id for group_id in group_ids if group_id not in existing_group_ids
    }

    if non_existent_group_ids:
        # Sort the ids so that the error message is consistent.
        repr_ids = sorted([repr(id_) for id_ in non_existent_group_ids])
        raise ResourceConflictError(f"Non-existent groups: {', '.join(repr_ids)}")

    return {"groups": group_ids}


async def update_mongo_user(
    user_id: str, mongo, pg: AsyncEngine, data: dict[str, Any], mongo_session, UserData
):
    """
    Update a user.

    Sessions and API keys are updated as well.

    :param mongo: the application MongoDB client
    :param pg: the application database object
    :param UserData: The User Datapiece
    :param user_id: the ID of the user to update
    :param data: the update data object
    :param mongo_session: the active MongoDB session
    :return: the updated user
    """
    document = await mongo.users.find_one(
        {"_id": user_id}, ["administrator", "groups"], session=mongo_session
    )

    if document is None:
        raise ResourceNotFoundError("User does not exist")

    updates = {}

    if "administrator" in data:
        updates["administrator"] = data["administrator"]

    if "force_reset" in data:
        updates.update(
            {
                "force_reset": data["force_reset"],
                "invalidate_sessions": True,
            }
        )

    if "password" in data:
        updates.update(
            {
                "password": virtool.users.utils.hash_password(data["password"]),
                "last_password_change": virtool.utils.timestamp(),
                "invalidate_sessions": True,
            }
        )

    if "groups" in data:
        try:
            updates.update(await compose_groups_update(pg, data["groups"]))

        except DatabaseError as err:
            raise ResourceConflictError(str(err))

    if "primary_group" in data:
        try:
            primary_group = await virtool.users.mongo.compose_primary_group_update(
                mongo,
                pg,
                data.get("groups", []),
                data["primary_group"],
                user_id,
            )

        except DatabaseError as err:
            raise ResourceConflictError(str(err))
        updates.update(primary_group)

    if "active" in data:
        updates.update({"active": data["active"], "invalidate_sessions": True})

    if updates:
        document = await mongo.users.find_one_and_update(
            {"_id": user_id}, {"$set": updates}, session=mongo_session
        )

        groups = []

        if document["groups"]:
            async with AsyncSession(pg) as pg_session:
                result = await pg_session.execute(
                    select(SQLGroup).where(
                        compose_legacy_id_expression(SQLGroup, document["groups"])
                    )
                )

            groups = [group.to_dict() for group in result.scalars().all()]

        await virtool.users.mongo.update_keys(
            mongo,
            user_id,
            document["administrator"],
            document["groups"],
            merge_group_permissions(groups),
            session=mongo_session,
        )
    return await UserData.get(user_id)
