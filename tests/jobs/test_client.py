import pytest

from virtool.jobs.client import JOB_REMOVED_FROM_QUEUE, JobsClient


@pytest.fixture
def jobs_client(mongo, redis):
    return JobsClient(redis)


@pytest.mark.parametrize("workflow", ["create_sample", "nuvs"])
async def test_enqueue(workflow, redis, jobs_client):
    """
    Test that a job ID is put in the correct job list when enqueued.

    """
    await jobs_client.enqueue(workflow, "foo")

    key = f"jobs_{workflow}"

    assert await redis.llen(key) == 1
    assert await redis.lpop(key) == "foo"


@pytest.mark.parametrize("workflow", ["nuvs", "create_sample"])
async def test_cancel_waiting(workflow, redis, jobs_client):
    """
    Test that a job ID is cancelled by removal when still in a Redis list.

    """
    await redis.rpush(f"jobs_{workflow}", "foo")

    list_keys = ["jobs_nuvs", "jobs_create_sample"]

    for key in list_keys:
        await redis.rpush(key, "bar", "foo", "baz", "boo")

    assert await jobs_client.cancel("foo") == JOB_REMOVED_FROM_QUEUE

    for key in list_keys:
        assert await redis.lrange(key, 0, 5) == [b"bar", b"baz", b"boo"]


async def test_cancel_running(mongo, redis, jobs_client):
    """
    Test that cancellation is published to 'channel:cancel' if the job ID is not in a
    list already.

    """
    (channel,) = await redis.subscribe("channel:cancel")

    await jobs_client.cancel("foo")

    # Check that job ID was published to cancellation channel.
    async for message in channel.listen():
        if message["type"] == "message":
            assert message["data"].decode() == "foo"
            break

    await channel.unsubscribe("channel:cancel")
