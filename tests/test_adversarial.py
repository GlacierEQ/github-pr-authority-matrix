from __future__ import annotations

from pr_authority_matrix import (
    Action,
    AuthorityGrant,
    Decision,
    GitHubRestExecutor,
    PrAuthorityMatrix,
    PrAuthorityMatrixRequest,
)


SECRET = b"adversarial-secret"
NOW = 1_800_000_000.0


def _grant(matrix: PrAuthorityMatrix, **overrides):
    params = {
        "grant_id": "g",
        "actor": "casey",
        "repository": "GlacierEQ/demo",
        "roles": ("admin",),
        "actions": ("label", "merge", "force_push"),
        "ttl_seconds": 300.0,
        "now": NOW,
    }
    params.update(overrides)
    return matrix.issue_grant(**params)


def _request(grant, *, actor="casey", repository="GlacierEQ/demo", action="label", context=None):
    return PrAuthorityMatrixRequest(
        subject_id="action",
        payload={
            "actor": actor,
            "repository": repository,
            "pr_number": 7,
            "action": action,
            "grant": grant.as_dict(),
            "context": context or {},
        },
        budget=1.0,
    )


def test_tampered_grant_mac_refuses() -> None:
    matrix = PrAuthorityMatrix(SECRET)
    grant = _grant(matrix)
    tampered = grant.as_dict()
    tampered["roles"] = ["admin", "maintain"]
    bad = AuthorityGrant.from_dict(tampered)
    receipt = matrix.evaluate(_request(bad), now=NOW + 1)

    assert receipt.decision is Decision.REFUSE
    assert "grant_bad_mac" in receipt.reasons


def test_actor_cannot_borrow_someone_elses_grant() -> None:
    matrix = PrAuthorityMatrix(SECRET)
    grant = _grant(matrix)
    receipt = matrix.evaluate(_request(grant, actor="intruder"), now=NOW + 1)

    assert receipt.decision is Decision.REFUSE
    assert "grant_actor_mismatch" in receipt.reasons


def test_grant_cannot_cross_repository_boundary() -> None:
    matrix = PrAuthorityMatrix(SECRET)
    grant = _grant(matrix)
    receipt = matrix.evaluate(_request(grant, repository="GlacierEQ/other"), now=NOW + 1)

    assert receipt.decision is Decision.REFUSE
    assert "grant_repository_mismatch" in receipt.reasons


def test_action_must_be_explicitly_granted() -> None:
    matrix = PrAuthorityMatrix(SECRET)
    grant = _grant(matrix, actions=("label",))
    receipt = matrix.evaluate(
        _request(
            grant,
            action="merge",
            context={"checks_passed": True, "approvals": 2, "required_approvals": 1, "mergeable": True},
        ),
        now=NOW + 1,
    )

    assert receipt.decision is Decision.REFUSE
    assert "grant_action_not_allowed" in receipt.reasons


def test_protected_branch_blocks_force_push_without_explicit_context_permission() -> None:
    matrix = PrAuthorityMatrix(SECRET)
    grant = _grant(matrix)
    receipt = matrix.evaluate(
        _request(
            grant,
            action=Action.FORCE_PUSH.value,
            context={"protected_branch": True, "target_ref": "refs/heads/main"},
        ),
        now=NOW + 1,
    )

    assert receipt.decision is Decision.REFUSE
    assert "protected_branch_force_push_blocked" in receipt.reasons


def test_future_dated_grant_refuses() -> None:
    matrix = PrAuthorityMatrix(SECRET)
    grant = _grant(matrix, now=NOW + 100)
    receipt = matrix.evaluate(_request(grant), now=NOW)

    assert receipt.decision is Decision.REFUSE
    assert "grant_not_yet_valid" in receipt.reasons


def test_github_executor_routes_label_without_network() -> None:
    executor = GitHubRestExecutor("token")
    captured = {}

    def fake_request(method, path, body):
        captured.update({"method": method, "path": path, "body": body})
        return {"ok": True}

    executor._request = fake_request  # type: ignore[method-assign]
    result = executor("label", "GlacierEQ/demo", 9, {"labels": ["ready", "tested"]})

    assert result == {"ok": True}
    assert captured == {
        "method": "POST",
        "path": "/repos/GlacierEQ/demo/issues/9/labels",
        "body": {"labels": ["ready", "tested"]},
    }


def test_builtin_executor_refuses_force_push_boundary() -> None:
    executor = GitHubRestExecutor("token")
    try:
        executor("force_push", "GlacierEQ/demo", 9, {})
    except ValueError as error:
        assert str(error) == "force_push_requires_separate_executor"
    else:
        raise AssertionError("force_push unexpectedly dispatched")
