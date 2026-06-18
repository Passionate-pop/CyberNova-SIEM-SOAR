"""
Chaos: Leader Election Failover
Scenario: Kill the leader instance; assert a new leader is elected and pipeline recovers.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybernova.ha.leader import LeaderElection


@pytest.mark.asyncio
async def test_follower_takes_over_when_leader_dies():
    """Kill the leader — follower detects expired lock and becomes leader."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)

    calls = []

    async def mock_set(key, value, nx=None, ex=None):
        calls.append(("set", key, value, nx))
        if len(calls) == 1:
            return True
        existing = await redis.get(key)
        return existing is None

    redis.set = AsyncMock(side_effect=mock_set)
    redis.get = AsyncMock(return_value=b"leader-instance")
    redis.delete = AsyncMock(return_value=True)
    redis.eval = AsyncMock(return_value=1)

    leader = LeaderElection(instance_id="leader-instance")
    follower = LeaderElection(instance_id="follower-instance")

    with patch("cybernova.ha.leader.get_redis", return_value=redis), \
         patch("cybernova.ha.leader.HEARTBEAT_INTERVAL", 0.05), \
         patch("cybernova.ha.leader.HEALTH_CHECK_INTERVAL", 0.05):

        await leader.start()
        await follower.start()

        await asyncio.sleep(0.15)
        assert leader.is_leader is True
        assert follower.is_leader is False

        follower_gained = False

        async def on_gained():
            nonlocal follower_gained
            follower_gained = True

        follower.on_leadership_gained(on_gained)

        redis.get.return_value = None

        await leader.stop()
        await asyncio.sleep(0.3)

        assert follower.is_leader is True
        assert follower_gained is True

    await follower.stop()


@pytest.mark.asyncio
async def test_both_instances_become_leader_when_redis_down():
    """No Redis — all instances become leader (local_mode fallback)."""
    with patch("cybernova.ha.leader.get_redis", return_value=None):
        a = LeaderElection(instance_id="instance-a")
        b = LeaderElection(instance_id="instance-b")

        await a.start()
        await b.start()

        await asyncio.sleep(0.05)
        assert a.is_leader is True
        assert b.is_leader is True
        assert a._local_mode is True

        await a.stop()
        await b.stop()


@pytest.mark.asyncio
async def test_leader_renews_lock_heartbeat():
    """Leader periodically renews lock before TTL expires."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.set = AsyncMock(return_value=True)

    eval_results = [1] * 10
    redis.eval = AsyncMock(side_effect=eval_results)

    leader = LeaderElection(instance_id="renewer")

    with patch("cybernova.ha.leader.get_redis", return_value=redis), \
         patch("cybernova.ha.leader.HEARTBEAT_INTERVAL", 0.05):

        await leader.start()
        await asyncio.sleep(0.15)

        assert leader.is_leader is True
        assert redis.eval.await_count >= 2

        await leader.stop()


@pytest.mark.asyncio
async def test_get_leader_status_reflects_state():
    """Leader status accurately reports current state (local mode)."""
    with patch("cybernova.ha.leader.get_redis", return_value=None):
        inst = LeaderElection(instance_id="status-test")
        await inst.start()

        await asyncio.sleep(0.05)
        status = await inst.get_leader_status()
        assert status["is_leader"] is True
        assert status["instance_id"] == "status-test"
        assert status["local_mode"] is True

        await inst.stop()

        status = await inst.get_leader_status()
        assert status["running"] is False
        assert status["is_leader"] is False


@pytest.mark.asyncio
async def test_leadership_controller_wires_callbacks():
    """LeadershipController registers callbacks and activates pipeline on gain."""
    from cybernova.ha.leadership import LeadershipController
    from cybernova.ha import leader_election as le

    controller = LeadershipController()
    gained = False

    async def on_gained():
        nonlocal gained
        gained = True

    controller.register_task("test", on_gained, lambda: None)

    le._is_leader = True
    le._local_mode = True

    with patch("cybernova.ha.leadership.unified_pipeline._running", True):
        await controller.start()
        await asyncio.sleep(0.05)

        assert controller.is_active is True

    le._is_leader = False


@pytest.mark.asyncio
async def test_pipeline_aware_rejects_when_not_leader():
    """PipelineAware wrapper raises NotLeaderError if we're not the leader."""
    from cybernova.ha.pipeline_aware import leader_aware_pipeline, NotLeaderError
    from cybernova.ha.leader import leader_election as le

    async def dummy_ingest(*args, **kwargs):
        return {"status": "ok"}

    with patch.object(le, '_is_leader', False), \
         patch.object(le, '_local_mode', False):
        with pytest.raises(NotLeaderError):
            await leader_aware_pipeline.ingest(dummy_ingest, "test")
