from __future__ import annotations

from pr_authority_matrix import (
    Action,
    Decision,
    PrAuthorityMatrix,
    PrAuthorityMatrixRequest,
    RecordingExecutor,
)


SECRET = b"test-secret"
NOW = 1_800_000_000.0


def _matrix() -> PrAuthorityMatrix:
    return PrAuthorityMatrix(SECRET)


def _grant(matrix: PrAuthorityMatrix, *, roles=("maintain",), actions=("label", "merge"), ttl=300.0):
    return matrix.issue_grant(
        grant_id="g-1",
        actor="casey",
        repository="GlacierEQ/demo",
        roles=roles,
        actions=actions,
        ttl_seconds=ttl,
        now=NOW,
    )


def _request(grant, *, action="label", context=None, side_effect=None, repository="GlacierEQ/demo"):
    return PrAuthorityMatrixRequest(
        subject_id="pr-42-action",
        payload={
            "actor": "casey",
            "repository": repository,
            "pr_number": 42,
            "action": action,
            "grant": grant.as_dict(),
            "context": context or {},
            "side_effect": side_effect or {},
        },
        budget=1.0,
    )


def test_secret_is_required() -> None:
    try:
        PrAuthorityMatrix(b"")
    except ValueError as error:
        assert str(error) == "secret_required"
    else:
        raise AssertionError("empty secret accepted")


def test_signed_grant_allows_authorized_label() -> None:
    matrix = _matrix()
    grant = _grant(matrix)
    receipt = matrix.evaluate(_request(grant), now=NOW + 10)

    assert receipt.decision is Decision.ALLOW
    assert receipt.reasons == ("authority_verified",)
    assert receipt.grant_id == "g-1"
    assert receipt.metrics["required_role"] == "triage"
    assert len(receipt.digest) == 64


def test_expired_grant_refuses() -> None:
    matrix = _matrix()
    grant = _grant(matrix, ttl=5)
    receipt = matrix.evaluate(_request(grant), now=NOW + 6)

    assert receipt.decision is Decision.REFUSE
    assert "grant_expired" in receipt.reasons


def test_revoked_grant_refuses_and_emits_revocation_receipt() -> None:
    matrix = _matrix()
    grant = _grant(matrix)
    revocation = matrix.revoke(grant.grant_id, "rotation", now=NOW + 20)
    receipt = matrix.evaluate(_request(grant), now=NOW + 21)

    assert len(revocation["digest"]) == 64
    assert receipt.decision is Decision.REFUSE
    assert "grant_revoked" in receipt.reasons


def test_merge_requires_runtime_preconditions() -> None:
    matrix = _matrix()
    grant = _grant(matrix)
    blocked = matrix.evaluate(
        _request(
            grant,
            action=Action.MERGE.value,
            context={"checks_passed": False, "approvals": 0, "required_approvals": 1, "mergeable": True},
        ),
        now=NOW + 10,
    )
    allowed = matrix.evaluate(
        _request(
            grant,
            action=Action.MERGE.value,
            context={"checks_passed": True, "approvals": 2, "required_approvals": 1, "mergeable": True, "draft": False},
        ),
        now=NOW + 10,
    )

    assert blocked.decision is Decision.REFUSE
    assert "required_checks_not_passed" in blocked.reasons
    assert "required_approvals_missing" in blocked.reasons
    assert allowed.decision is Decision.ALLOW


def test_dispatch_calls_executor_only_after_allow() -> None:
    matrix = _matrix()
    grant = _grant(matrix)
    executor = RecordingExecutor()
    result = matrix.dispatch(
        _request(grant, side_effect={"labels": ["ready"]}),
        executor,
        now=NOW + 10,
    )

    assert result["attempted"] is True
    assert result["executed"] is True
    assert result["outcome"] == "EXECUTED"
    assert result["result"]["ok"] is True
    assert executor.calls == [
        {
            "action": "label",
            "repository": "GlacierEQ/demo",
            "pr_number": 42,
            "data": {"labels": ["ready"]},
        }
    ]


def test_refused_dispatch_never_calls_executor() -> None:
    matrix = _matrix()
    grant = _grant(matrix, ttl=1)
    executor = RecordingExecutor()
    result = matrix.dispatch(_request(grant), executor, now=NOW + 2)

    assert result["attempted"] is False
    assert result["executed"] is False
    assert result["outcome"] == "REFUSED"
    assert executor.calls == []
    assert result["authority"]["decision"] == "REFUSE"


def test_executor_error_becomes_structured_failure() -> None:
    matrix = _matrix()
    grant = _grant(matrix)

    def failing_executor(action, repository, pr_number, data):
        raise RuntimeError("remote unavailable")

    result = matrix.dispatch(_request(grant), failing_executor, now=NOW + 10)

    assert result["attempted"] is True
    assert result["executed"] is False
    assert result["outcome"] == "EXECUTOR_ERROR"
    assert result["error"] == {"type": "RuntimeError", "message": "remote unavailable"}
    assert len(result["digest"]) == 64


def test_insufficient_role_refuses_merge() -> None:
    matrix = _matrix()
    grant = _grant(matrix, roles=("write",), actions=("merge",))
    receipt = matrix.evaluate(
        _request(
            grant,
            action="merge",
            context={"checks_passed": True, "approvals": 2, "required_approvals": 1, "mergeable": True},
        ),
        now=NOW + 10,
    )

    assert receipt.decision is Decision.REFUSE
    assert "grant_role_insufficient" in receipt.reasons
