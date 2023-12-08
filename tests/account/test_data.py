import asyncio
import datetime

import pytest
from aiohttp.test_utils import make_mocked_coro
from syrupy.filters import props
from syrupy.matchers import path_type
from virtool_core.models.enums import Permission
from virtool_core.models.roles import AdministratorRole

from virtool.account.oas import CreateKeysRequest, UpdateAccountRequest
from virtool.groups.oas import PermissionsUpdate
from virtool.pg.utils import get_row_by_id
from virtool.users.pg import SQLUser

_last_password_change_matcher = path_type(
    {"last_password_change": (datetime.datetime,)}
)


@pytest.mark.parametrize(
    "administrator_role", [AdministratorRole.FULL, None], ids=["full", "none"]
)
@pytest.mark.parametrize(
    "has_permission", [True, False], ids=["has permission", "missing permission"]
)
async def test_create_api_key(
    administrator_role,
    has_permission,
    mocker,
    mongo,
    snapshot,
    static_time,
    data_layer,
    fake2,
):
    """
    Test that an API key is created correctly with varying key owner administrator status and
    permissions.

    """
    mocker.patch("virtool.account.db.get_alternate_id", make_mocked_coro("foo_0"))

    mocker.patch("virtool.utils.generate_key", return_value=("bar", "baz"))

    group_1 = await fake2.groups.create()
    group_2 = await fake2.groups.create(
        PermissionsUpdate(
            **{
                Permission.create_sample: True,
                Permission.modify_subtraction: has_permission,
            }
        )
    )

    user = await fake2.users.create(
        groups=[group_1, group_2], administrator_role=administrator_role
    )

    _, api_key = await data_layer.account.create_key(
        CreateKeysRequest(
            name="Foo",
            permissions=PermissionsUpdate(create_sample=True, modify_subtraction=True),
        ),
        user.id,
    )

    assert api_key == snapshot(name="dl")
    assert await mongo.keys.find_one() == snapshot(name="mongo")


@pytest.mark.parametrize(
    "update",
    [
        UpdateAccountRequest(old_password="hello_world_1", password="hello_world_2"),
        UpdateAccountRequest(email="hello@world.com"),
        UpdateAccountRequest(
            old_password="hello_world_1",
            password="hello_world_2",
            email="hello@world.com",
        ),
    ],
    ids=["password", "email", "password and email"],
)
async def test_update(data_layer, mongo, pg, fake2, snapshot, update):
    user = await fake2.users.create(password="hello_world_1")

    await data_layer.account.update(
        user.id,
        update,
    )

    (row, document) = await asyncio.gather(
        get_row_by_id(pg, SQLUser, 1), mongo.users.find_one({"_id": user.id})
    )

    assert row == snapshot(
        name="pg", matcher=_last_password_change_matcher, exclude=props("password")
    )
    assert document == snapshot(
        name="mongo", matcher=_last_password_change_matcher, exclude=props("password")
    )
    assert row.password == document["password"]
