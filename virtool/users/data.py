import asyncio
import random
from typing import Any


from pymongo.errors import DuplicateKeyError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import selectinload
from virtool_core.models.roles import AdministratorRole
from virtool_core.models.user import User, UserSearchResult

import virtool.users.utils
import virtool.utils
from virtool.administrators.db import update_legacy_administrator
from virtool.api.utils import compose_regex_query, paginate_aggregate
from virtool.authorization.client import AuthorizationClient
from virtool.authorization.relationships import AdministratorRoleAssignment
from virtool.data.domain import DataLayerDomain
from virtool.data.errors import ResourceConflictError, ResourceNotFoundError
from virtool.data.events import emits, Operation
from virtool.data.topg import compose_legacy_id_expression, both_transactions
from virtool.data.transforms import apply_transforms
from virtool.errors import DatabaseError
from virtool.groups.pg import merge_group_permissions, SQLGroup
from virtool.groups.transforms import AttachPrimaryGroupTransform, AttachGroupsTransform
from virtool.mongo.core import Mongo
from virtool.mongo.utils import id_exists
from virtool.users.db import (
    B2CUserAttributes,
    compose_groups_update,
    update_mongo_user,
)
from virtool.users.mongo import (
    create_user,
    update_keys,
    compose_primary_group_update,
)
from virtool.users.oas import UpdateUserRequest
from virtool.users.pg import SQLUser
from virtool.users.transforms import AttachPermissionsTransform
from virtool.utils import base_processor

PROJECTION = [
    "_id",
    "handle",
    "administrator",
    "force_reset",
    "groups",
    "last_password_change",
    "permissions",
    "primary_group",
    "administrator_role",
    "active",
    "b2c",
    "b2c_display_name",
    "b2c_family_name",
    "b2c_given_name",
    "b2c_oid",
]


class UsersData(DataLayerDomain):
    name = "users"

    def __init__(
        self, authorization_client: AuthorizationClient, mongo: Mongo, pg: AsyncEngine
    ):
        self._authorization_client = authorization_client
        self._mongo = mongo
        self._pg = pg

    async def find(
        self,
        page: int,
        per_page: int,
        administrator: bool | None = None,
        term: str | None = None,
    ) -> UserSearchResult:
        """
        Find users.

        Optionally filter by administrator status or search term.

        :param page: the page number
        :param per_page: the number of items per page
        :param administrator: whether to filter by administrator status
        :param term: a search term to filter by user handle
        """

        administrator_roles = dict(
            await self._authorization_client.list_administrators()
        )

        administrator_query = {}

        if administrator is not None:
            operator = "$in" if administrator else "$nin"
            administrator_query = {"_id": {operator: list(administrator_roles.keys())}}

        term_query = compose_regex_query(term, ["handle"]) if term else {}

        client_query = {**administrator_query, **term_query}

        result = await paginate_aggregate(
            self._mongo.users,
            page,
            per_page,
            client_query,
            sort="handle",
            projection={field: True for field in PROJECTION},
        )

        result["items"] = await apply_transforms(
            [base_processor(item) for item in result["items"]],
            [
                AttachPermissionsTransform(self._pg),
                AttachPrimaryGroupTransform(self._pg),
                AttachGroupsTransform(self._pg),
            ],
        )

        result["items"] = [
            User(**user, administrator_role=administrator_roles.get(user["id"]))
            for user in result["items"]
        ]

        return UserSearchResult(**result)

    async def get(self, user_id: str) -> User:
        """
        Get a user by their ``user_id``.

        :param user_id: the user's ID
        :return: the user
        """
        user, (user_id, role) = await asyncio.gather(
            self._mongo.users.find_one(
                {"_id": user_id},
            ),
            self._authorization_client.get_administrator(user_id),
        )

        if not user:
            raise ResourceNotFoundError("User does not exist")

        return User(
            **(
                await apply_transforms(
                    base_processor(user),
                    [
                        AttachPermissionsTransform(self._pg),
                        AttachPrimaryGroupTransform(self._pg),
                        AttachGroupsTransform(self._pg),
                    ],
                )
            ),
            administrator_role=role,
        )

    @emits(Operation.CREATE)
    async def create(
        self,
        handle: str,
        password: str,
        force_reset: bool = False,
    ) -> User:
        """
        Create a new user.

        :param handle: the requested handle for the user
        :param password: a password
        :param force_reset: force the user to reset password on next login
        :return: the user document
        """
        async with both_transactions(self._mongo, self._pg) as (
            mongo_session,
            pg_session,
        ):
            document = await create_user(
                self._mongo,
                handle,
                password,
                force_reset,
                session=mongo_session,
            )

            pg_session.add(
                SQLUser(
                    legacy_id=document["_id"],
                    handle=handle,
                    password=document["password"],
                    force_reset=force_reset,
                    last_password_change=virtool.utils.timestamp(),
                )
            )

        return await self.get(document["_id"])

    @emits(Operation.CREATE)
    async def create_b2c(
        self,
        handle: str,
        b2c_user_attributes: B2CUserAttributes,
        force_reset: bool = False,
    ) -> User:
        """
        Create a new user using Azure B2C information.

        :param handle: the requested handle for the user
        :param force_reset: force the user to reset password on next login
        :param  b2c_user_attributes: Azure b2c user attributes used to describe a user
        :return: the user document
        """
        async with both_transactions(self._mongo, self._pg) as (
            mongo_session,
            pg_session,
        ):
            document = await create_user(
                self._mongo,
                handle,
                None,
                force_reset,
                b2c_user_attributes=b2c_user_attributes,
                session=mongo_session,
            )

            pg_session.add(
                SQLUser(
                    legacy_id=document["_id"],
                    handle=handle,
                    password=None,
                    force_reset=force_reset,
                    last_password_change=virtool.utils.timestamp(),
                    b2c_display_name=b2c_user_attributes.display_name,
                    b2c_given_name=b2c_user_attributes.given_name,
                    b2c_family_name=b2c_user_attributes.family_name,
                    b2c_oid=b2c_user_attributes.oid,
                )
            )

        return await self.get(document["_id"])

    async def create_first(self, handle: str, password: str) -> User:
        """
        Create the first instance user.

        :param handle: the user handle
        :param password: the password
        :return: the user created
        """
        if await self.check_users_exist():
            raise ResourceConflictError("Virtool already has at least one user")

        if handle == "virtool":
            raise ResourceConflictError("Reserved user name: virtool")

        document = await self.create(handle, password)

        await self.set_administrator_role(document.id, AdministratorRole.FULL)

        return await self.get(document.id)

    async def find_or_create_b2c_user(
        self, b2c_user_attributes: B2CUserAttributes
    ) -> User:
        """
        Search for existing user using an OID.

        If not found, create new user with the OID and user attributes. Auto-generate a
        handle.

        :param b2c_user_attributes: User attributes collected from ID token claims
        :return: the found or created user
        """
        if document := await self._mongo.users.find_one(
            {"b2c_oid": b2c_user_attributes.oid}, ["_id"]
        ):
            return await self.get(document["_id"])

        handle = f"{b2c_user_attributes.given_name}-{b2c_user_attributes.family_name}-{random.randint(1, 100)}"

        while await self._mongo.users.count_documents({"handle": handle}):
            handle = f"{b2c_user_attributes.given_name}-{b2c_user_attributes.family_name}-{random.randint(1, 100)}"

        try:
            user = await self.create_b2c(handle, b2c_user_attributes)
        except DuplicateKeyError:
            return await self.find_or_create_b2c_user(b2c_user_attributes)

        return user

    async def set_administrator_role(
        self, user_id: str, role: AdministratorRole
    ) -> User:
        """
        Set a user's administrator role.

        Sets the user's legacy administrator flag to ``True`` if the ``FULL`` user role
        is set. Otherwise, sets the flag to ``False``.

        :param user_id: the id of the user to set the role of
        :param role: the administrator role
        :return: the administrator
        """

        if not await id_exists(self._mongo.users, user_id):
            raise ResourceNotFoundError("User does not exist")

        async with both_transactions(self._mongo, self._pg) as (
            mongo_session,
            pg_session,
        ):
            await asyncio.gather(
                update_legacy_administrator(self._mongo, user_id, role, mongo_session),
                pg_session.execute(
                    update(SQLUser)
                    .where(SQLUser.legacy_id == user_id)
                    .values(administrator=role == AdministratorRole.FULL)
                ),
            )

            if role is None:
                # Clear the user's administrator role.
                admin_tuple = await self._authorization_client.get_administrator(
                    user_id
                )

                if admin_tuple[1] is not None:
                    await self._authorization_client.remove(
                        AdministratorRoleAssignment(
                            user_id, AdministratorRole(admin_tuple[1])
                        )
                    )
            else:
                await self._authorization_client.add(
                    AdministratorRoleAssignment(user_id, AdministratorRole(role))
                )

        user = await self.get(user_id)

        return user

    @emits(Operation.UPDATE)
    async def update(self, user_id: str, data: UpdateUserRequest):
        """
        Update a user.

        Sessions and API keys are updated as well.

        :param user_id: the ID of the user to update
        :param data: the update data object
        :return: the updated user
        """
        async with both_transactions(self._mongo, self._pg) as (
            mongo_session,
            pg_session,
        ):
            data = data.dict(exclude_unset=True)
            mongo_user = await update_mongo_user(
                user_id, self._mongo, self._pg, data, mongo_session, self
            )

            user = (
                await pg_session.execute(
                    select(SQLUser)
                    .where(SQLUser.legacy_id == user_id)
                    .limit(1)
                    .options(selectinload(SQLUser.groups))
                )
            ).scalar()

            if user is None:
                return mongo_user

            if "administrator" in data:
                user.administrator = data["administrator"]

                role_assignment = AdministratorRoleAssignment(
                    user_id, AdministratorRole.FULL
                )

                if data["administrator"]:
                    await self._authorization_client.add(role_assignment)
                else:
                    await self._authorization_client.remove(role_assignment)

            if "force_reset" in data:
                user.force_reset = data["force_reset"]
                user.invalidate_sessions = True

            if "password" in data:
                user.password = virtool.users.utils.hash_password(data["password"])
                user.last_password_change = virtool.utils.timestamp()
                user.invalidate_sessions = True

            if "groups" in data:
                try:
                    user.groups = (
                        (
                            await pg_session.execute(
                                select(SQLGroup).where(SQLGroup.id.in_(data["groups"]))
                            )
                        )
                        .scalars()
                        .all()
                    )

                except DatabaseError as err:
                    raise ResourceConflictError(str(err))

            if "primary_group" in data:
                try:
                    user.primary_group_id = data["primary_group"]
                    user.primary_group = (
                        await pg_session.execute(
                            select(SQLGroup).where(SQLGroup.id == data["primary_group"])
                        )
                    ).scalar()
                    if user.primary_group not in user.groups:
                        raise DatabaseError("User not in Primary Group")

                except DatabaseError as err:
                    raise ResourceConflictError(str(err))

            if "active" in data:
                user.active = data["active"]
                user.invalidate_sessions = True

        return await self.get(user_id)

    async def check_users_exist(self) -> bool:
        """
        Checks that users exist.

        :returns: True if users exist otherwise False
        """
        return await self._mongo.users.count_documents({}, limit=1) > 0
