import asyncio
import datetime
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from syrupy import SnapshotAssertion
from syrupy.filters import props
from syrupy.matchers import path_type
from virtool_core.models.roles import AdministratorRole

from virtool.authorization.client import AuthorizationClient
from virtool.authorization.relationships import AdministratorRoleAssignment
from virtool.data.errors import ResourceConflictError, ResourceNotFoundError
from virtool.data.layer import DataLayer
from virtool.fake.next import DataFaker
from virtool.mongo.core import Mongo
from virtool.mongo.utils import get_one_field
from virtool.pg.utils import get_row_by_id
from virtool.users.db import B2CUserAttributes
from virtool.users.mongo import validate_credentials
from virtool.users.oas import UpdateUserRequest
from virtool.users.pg import SQLUser, user_group_associations

_last_password_change_matcher = path_type(
    {"last_password_change": (datetime.datetime,)}
)


@pytest.fixture(params=[0, 1, 2])
async def groups(
    fake2,
):
    groups = []
    for _ in range(request.param):
        groups.append(await fake2.groups.create())
    return groups


class TestCreate:
    async def test_no_force_reset(
        self,
        data_layer: DataLayer,
        mongo: Mongo,
        pg: AsyncEngine,
        snapshot: SnapshotAssertion,
    ):
        user = await data_layer.users.create(password="hello_world", handle="bill")
        assert user.force_reset is False
        assert user == snapshot(
            name="obj",
            exclude=props(
                "id",
            ),
            matcher=_last_password_change_matcher,
        )

        row, doc = await asyncio.gather(
            get_row_by_id(pg, SQLUser, 1), mongo.users.find_one({"_id": user.id})
        )

        assert row.to_dict() == snapshot(
            name="pg",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )

        assert doc == snapshot(
            name="mongo",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )

        assert doc["password"] == row.password

    @pytest.mark.parametrize("force_reset", [True, False])
    async def test_force_reset(
        self,
        force_reset: bool,
        data_layer: DataLayer,
        mongo: Mongo,
        pg: AsyncEngine,
        snapshot: SnapshotAssertion,
    ):
        user = await data_layer.users.create(
            force_reset=force_reset, password="hello_world", handle="bill"
        )

        assert user.force_reset == force_reset
        assert user == snapshot(
            exclude=props(
                "id",
            ),
            matcher=_last_password_change_matcher,
        )

        row, doc = await asyncio.gather(
            get_row_by_id(pg, SQLUser, 1), mongo.users.find_one({"_id": user.id})
        )

        assert row.to_dict() == snapshot(
            name="pg",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )

        assert doc == snapshot(
            name="mongo",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )

        assert doc["password"] == row.password

    async def test_already_exists(
        self, data_layer: DataLayer, fake2: DataFaker, mongo: Mongo
    ):
        """
        Test that an error is raised when a user with the same handle already exists.
        """
        await mongo.users.create_index("handle", unique=True, sparse=True)

        user = await fake2.users.create()

        with pytest.raises(ResourceConflictError) as err:
            await data_layer.users.create(password="hello_world", handle=user.handle)
            assert "User already exists" in str(err)

    async def test_create_first(
        self,
        data_layer: DataLayer,
        mongo: Mongo,
        pg: AsyncEngine,
        snapshot: SnapshotAssertion,
    ):
        user = await data_layer.users.create_first(
            password="hello_world", handle="bill"
        )

        assert user == snapshot(
            exclude=props(
                "id",
            ),
            matcher=_last_password_change_matcher,
        )

        async with (AsyncSession(pg) as session):
            row = await session.get(SQLUser, 1)

        assert row.to_dict() == snapshot(
            name="pg",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )

        doc = await mongo.users.find_one({"_id": user.id})
        assert doc == snapshot(
            name="mongo",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )

        assert doc["password"] == row.password
        assert doc["administrator"] == row.administrator


class TestUpdate:
    @pytest.mark.parametrize("is_administrator", [True, False])
    async def test_administrator(
        self,
        is_administrator: bool,
        authorization_client: AuthorizationClient,
        data_layer: DataLayer,
        fake2: DataFaker,
        mongo: Mongo,
        pg: AsyncEngine,
        snapshot: SnapshotAssertion,
    ):
        """
        Test that setting a user to administrator and vice versa sets the legacy
        ``administrator`` flag and gives them the ``AdministratorRole.FULL`` role.
        """
        user = await fake2.users.create(administrator_role=AdministratorRole.FULL)

        assert await data_layer.users.update(
            user.id, UpdateUserRequest(administrator=not is_administrator)
        ) == snapshot(
            name="obj",
            matcher=_last_password_change_matcher,
        )

        assert await mongo.users.find_one() == snapshot(
            name="mongo",
            exclude=props("password"),
            matcher=_last_password_change_matcher,
        )
        async with (AsyncSession(pg) as session):
            row = await session.get(SQLUser, 1)

            assert row.to_dict() == snapshot(
                name="pg",
                exclude=props("password"),
                matcher=_last_password_change_matcher,
            )

        assert (
            await authorization_client.list_administrators() == []
            if is_administrator
            else [(user.id, "full")]
        )

    async def test_force_reset(
        self, data_layer: DataLayer, fake2: DataFaker, mongo: Mongo, pg: AsyncEngine
    ):
        """
        Test that setting and unsetting ``force_reset`` works as expected.
        """
        user = await fake2.users.create()

        assert user.force_reset is False
        async with (AsyncSession(pg) as session):
            row = await session.get(SQLUser, 1)

        assert row.force_reset is False

        user = await data_layer.users.update(
            user.id, UpdateUserRequest(force_reset=True)
        )

        async with (AsyncSession(pg) as session):
            row = await session.get(SQLUser, 1)

        assert user.force_reset is True
        assert row.force_reset is True

        user = await data_layer.users.update(
            user.id, UpdateUserRequest(force_reset=False)
        )

        async with (AsyncSession(pg) as session):
            row = await session.get(SQLUser, 1)

        assert user.force_reset is False
        assert row.force_reset is False

    @pytest.mark.parametrize("groups", [0, 1, 2])
    async def test_set_groups(
        self,
        data_layer: DataLayer,
        fake2: DataFaker,
        pg: AsyncEngine,
        snapshot: SnapshotAssertion,
        groups,
    ):
        """
        Test that setting ``groups`` works as expected.
        """
        user = await fake2.users.create()

        async with (AsyncSession(pg) as session):
            groups = await session.execute(
                select(user_group_associations).where(
                    user_group_associations.c.user_id == SQLUser.id
                )
            )
            row = await session.get(SQLUser, 1)
        assert groups.mappings().all() == snapshot(name="groups_mapping_before")
        assert user.groups == snapshot(name="groups_before")
        assert user == snapshot(
            name="mongo_before", matcher=_last_password_change_matcher
        )
        assert row == snapshot(name="pg_before")

        user = await data_layer.users.update(
            user.id, UpdateUserRequest(groups=[group.id for group in groups])
        )

        async with (AsyncSession(pg) as session):
            groups = await session.execute(
                select(user_group_associations).where(
                    user_group_associations.c.user_id == SQLUser.id
                )
            )
            row = await session.get(SQLUser, 1)
        assert groups.mappings().all() == snapshot(name="groups_mapping_after")
        assert user.groups == snapshot(name="groups_after")
        assert user == snapshot(
            name="mongo_after", matcher=_last_password_change_matcher
        )
        assert row == snapshot(name="pg_after")

    async def test_password(
        self,
        data_layer: DataLayer,
        mongo: Mongo,
        pg: AsyncEngine,
        snapshot: SnapshotAssertion,
    ):
        """
        Test editing an existing user.

        """
        user = await data_layer.users.create("bob", "password")

        assert await data_layer.users.update(
            user.id, UpdateUserRequest(password="hello_world")
        ) == snapshot(name="obj", matcher=_last_password_change_matcher)

        assert await mongo.users.find_one() == snapshot(
            name="db", exclude=props("password"), matcher=_last_password_change_matcher
        )

        async with (AsyncSession(pg) as session):
            row = await session.get(SQLUser, 1)

            assert row.to_dict() == snapshot(
                name="pg",
                exclude=props("password"),
                matcher=_last_password_change_matcher,
            )

        # Ensure the newly set password validates.
        assert await validate_credentials(mongo, user.id, "hello_world")

    async def test_not_found(self, data_layer: DataLayer):
        with pytest.raises(ResourceNotFoundError) as err:
            await data_layer.users.update(
                "user_id", UpdateUserRequest(administrator=False)
            )

        assert "User does not exist" == str(err.value)


@pytest.mark.parametrize("exists", [True, False])
async def test_find_or_create_b2c_user(
    exists: bool,
    data_layer: DataLayer,
    fake2: DataFaker,
    mongo: Mongo,
    snapshot: SnapshotAssertion,
    static_time,
):
    fake_user = await fake2.users.create()

    await mongo.users.update_one(
        {"_id": fake_user.id},
        {
            "$set": {
                "last_password_change": static_time.datetime,
                "force_reset": False,
                "b2c_oid": "abc123" if exists else "def456",
                "b2c_given_name": "Bilbo",
                "b2c_family_name": "Baggins",
                "b2c_display_name": "Bilbo",
            }
        },
    )

    user = await data_layer.users.find_or_create_b2c_user(
        B2CUserAttributes(
            oid="abc123",
            display_name="Fred",
            given_name="Fred",
            family_name="Smith",
        )
    )

    if not exists:
        assert "Fred-Smith" in user.handle
        # Make sure handle ends with integer.
        assert int(user.handle.split("-")[-1])

    assert user == snapshot(matcher=path_type({"handle": (str,)}))


class TestCheckUsersExist:
    async def test_no_users_exist(self, data_layer: DataLayer):
        """
        Verify that the user existence check returns False when no users exist.
        """
        assert not await data_layer.users.check_users_exist()

    async def test_users_exist(self, data_layer: DataLayer):
        """
        Verify that the user existence check returns True when users exist.
        """
        await data_layer.users.create(password="hello_world", handle="bill")
        assert await data_layer.users.check_users_exist()


@pytest.mark.parametrize("role", [None, AdministratorRole.BASE, AdministratorRole.FULL])
async def test_set_administrator_role(
    role: AdministratorRole | None,
    authorization_client: AuthorizationClient,
    data_layer: DataLayer,
    fake2: DataFaker,
    mongo: Mongo,
    snapshot: SnapshotAssertion,
    static_time,
):
    """
    Test changing the administrator role of a user.

    """
    user = await fake2.users.create()

    assert await data_layer.users.set_administrator_role(user.id, role) == snapshot(
        name="obj"
    )

    assert await get_one_field(mongo.users, "administrator", user.id) == (
        role == AdministratorRole.FULL
    )

    assert await authorization_client.list_administrators() == (
        [(user.id, role)] if role is not None else []
    )


@pytest.mark.parametrize("term", [None, "test_user", "missing-handle"])
@pytest.mark.parametrize("administrator", [True, False, None])
async def test_find_users(
    term: str | None,
    administrator: bool | None,
    authorization_client: AuthorizationClient,
    data_layer: DataLayer,
    fake2: DataFaker,
    snapshot: SnapshotAssertion,
    static_time,
):
    group_1 = await fake2.groups.create()
    group_2 = await fake2.groups.create()

    user_1 = await fake2.users.create(
        handle="test_user", groups=[group_1, group_2], primary_group=group_1
    )
    user_2 = await fake2.users.create()
    await fake2.users.create()

    await authorization_client.add(
        AdministratorRoleAssignment(user_1.id, AdministratorRole.BASE),
        AdministratorRoleAssignment(user_2.id, AdministratorRole.FULL),
    )

    assert (
        await data_layer.users.find(1, 25, term=term, administrator=administrator)
        == snapshot
    )
