"""Signed PR authority, revocation, and side-effect dispatch engine."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


class Action(str, Enum):
    LABEL = "label"
    COMMENT = "comment"
    REQUEST_REVIEW = "request_review"
    UPDATE_BRANCH = "update_branch"
    MERGE = "merge"
    FORCE_PUSH = "force_push"


ROLE_RANK = {"read": 0, "triage": 1, "write": 2, "maintain": 3, "admin": 4}
ACTION_MIN_ROLE = {
    Action.LABEL.value: "triage",
    Action.COMMENT.value: "triage",
    Action.REQUEST_REVIEW.value: "write",
    Action.UPDATE_BRANCH.value: "write",
    Action.MERGE.value: "maintain",
    Action.FORCE_PUSH.value: "admin",
}


@dataclass(frozen=True)
class AuthorityGrant:
    grant_id: str
    actor: str
    repository: str
    roles: tuple[str, ...]
    actions: tuple[str, ...]
    issued_at: float
    not_after: float
    mac: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "actor": self.actor,
            "repository": self.repository,
            "roles": list(self.roles),
            "actions": list(self.actions),
            "issued_at": self.issued_at,
            "not_after": self.not_after,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "mac": self.mac}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuthorityGrant":
        return cls(
            grant_id=str(value["grant_id"]),
            actor=str(value["actor"]),
            repository=str(value["repository"]),
            roles=tuple(sorted({str(x).lower() for x in value.get("roles", [])})),
            actions=tuple(sorted({str(x).lower() for x in value.get("actions", [])})),
            issued_at=float(value["issued_at"]),
            not_after=float(value["not_after"]),
            mac=str(value["mac"]),
        )


@dataclass(frozen=True)
class PrAuthorityMatrixRequest:
    subject_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    budget: float = 1.0
    grant_id: str | None = None
    not_after: float | None = None


@dataclass(frozen=True)
class PrAuthorityMatrixReceipt:
    decision: Decision
    reasons: tuple[str, ...]
    digest: str
    metrics: dict[str, Any] = field(default_factory=dict)
    grant_id: str | None = None
    action: str | None = None
    repository: str | None = None
    actor: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "digest": self.digest,
            "metrics": self.metrics,
            "grant_id": self.grant_id,
            "action": self.action,
            "repository": self.repository,
            "actor": self.actor,
        }


class PrAuthorityMatrix:
    """Issue grants, revoke them, authorize actions, and dispatch side effects."""

    MIN_BUDGET = 0.0
    MAX_TTL_SECONDS = 24 * 60 * 60

    def __init__(self, secret: bytes):
        if not secret:
            raise ValueError("secret_required")
        self._secret = bytes(secret)
        self._revoked: dict[str, dict[str, Any]] = {}

    def _sign(self, unsigned: dict[str, Any]) -> str:
        return hmac.new(self._secret, _canonical(unsigned), hashlib.sha256).hexdigest()

    def issue_grant(
        self,
        *,
        grant_id: str,
        actor: str,
        repository: str,
        roles: list[str] | tuple[str, ...],
        actions: list[str] | tuple[str, ...],
        ttl_seconds: float,
        now: float | None = None,
    ) -> AuthorityGrant:
        if not str(grant_id).strip():
            raise ValueError("grant_id_required")
        if not str(actor).strip():
            raise ValueError("actor_required")
        if not str(repository).strip():
            raise ValueError("repository_required")
        if ttl_seconds <= 0 or ttl_seconds > self.MAX_TTL_SECONDS:
            raise ValueError("ttl_out_of_range")

        normalized_roles = tuple(sorted({str(role).lower() for role in roles}))
        normalized_actions = tuple(sorted({str(action).lower() for action in actions}))
        if not normalized_roles or any(role not in ROLE_RANK for role in normalized_roles):
            raise ValueError("roles_invalid")
        if not normalized_actions or any(action not in ACTION_MIN_ROLE for action in normalized_actions):
            raise ValueError("actions_invalid")

        issued_at = time.time() if now is None else float(now)
        unsigned = {
            "grant_id": str(grant_id),
            "actor": str(actor),
            "repository": str(repository),
            "roles": list(normalized_roles),
            "actions": list(normalized_actions),
            "issued_at": issued_at,
            "not_after": issued_at + float(ttl_seconds),
        }
        return AuthorityGrant(
            grant_id=unsigned["grant_id"],
            actor=unsigned["actor"],
            repository=unsigned["repository"],
            roles=normalized_roles,
            actions=normalized_actions,
            issued_at=issued_at,
            not_after=unsigned["not_after"],
            mac=self._sign(unsigned),
        )

    def revoke(self, grant_id: str, reason: str, *, now: float | None = None) -> dict[str, Any]:
        if not str(grant_id).strip():
            raise ValueError("grant_id_required")
        receipt = {
            "grant_id": str(grant_id),
            "reason": str(reason).strip() or "revoked",
            "revoked_at": time.time() if now is None else float(now),
        }
        receipt["digest"] = _digest(receipt)
        self._revoked[str(grant_id)] = receipt
        return dict(receipt)

    @staticmethod
    def _highest_role(roles: tuple[str, ...]) -> int:
        return max((ROLE_RANK.get(role, -1) for role in roles), default=-1)

    def _verify_grant(self, grant: AuthorityGrant, *, actor: str, repository: str, action: str, now: float) -> list[str]:
        failures: list[str] = []
        if not hmac.compare_digest(self._sign(grant.unsigned()), grant.mac):
            failures.append("grant_bad_mac")
        if grant.grant_id in self._revoked:
            failures.append("grant_revoked")
        if now < grant.issued_at:
            failures.append("grant_not_yet_valid")
        if now > grant.not_after:
            failures.append("grant_expired")
        if grant.actor != actor:
            failures.append("grant_actor_mismatch")
        if grant.repository not in {repository, "*"}:
            failures.append("grant_repository_mismatch")
        if action not in grant.actions:
            failures.append("grant_action_not_allowed")
        required = ACTION_MIN_ROLE.get(action)
        if required is None:
            failures.append("action_unknown")
        elif self._highest_role(grant.roles) < ROLE_RANK[required]:
            failures.append("grant_role_insufficient")
        return failures

    @staticmethod
    def _merge_preconditions(context: dict[str, Any]) -> list[str]:
        failures: list[str] = []
        if bool(context.get("draft", False)):
            failures.append("pr_is_draft")
        if context.get("checks_passed") is not True:
            failures.append("required_checks_not_passed")
        try:
            approvals = int(context.get("approvals", 0))
            required = int(context.get("required_approvals", 1))
        except (TypeError, ValueError):
            return failures + ["approval_state_invalid"]
        if approvals < required:
            failures.append("required_approvals_missing")
        if context.get("mergeable") is False:
            failures.append("pr_not_mergeable")
        return failures

    @staticmethod
    def _force_push_preconditions(context: dict[str, Any]) -> list[str]:
        failures: list[str] = []
        if bool(context.get("protected_branch", False)) and context.get("protected_force_push_allowed") is not True:
            failures.append("protected_branch_force_push_blocked")
        if not str(context.get("target_ref", "")).strip():
            failures.append("force_push_target_ref_missing")
        return failures

    def evaluate(self, req: PrAuthorityMatrixRequest, *, now: float | None = None) -> PrAuthorityMatrixReceipt:
        reasons: list[str] = []
        if not str(req.subject_id or "").strip():
            reasons.append("subject_id_missing")
        if req.budget <= self.MIN_BUDGET:
            reasons.append("budget_non_positive")
        payload = req.payload if isinstance(req.payload, dict) else {}
        if not isinstance(req.payload, dict):
            reasons.append("payload_not_object")

        actor = str(payload.get("actor", "")).strip()
        repository = str(payload.get("repository", "")).strip()
        action = str(payload.get("action", "")).strip().lower()
        if not actor:
            reasons.append("actor_missing")
        if not repository or "/" not in repository:
            reasons.append("repository_invalid")
        if action not in ACTION_MIN_ROLE:
            reasons.append("action_unknown")
        try:
            pr_number = int(payload.get("pr_number", 0))
            if pr_number <= 0:
                raise ValueError
        except (TypeError, ValueError):
            pr_number = 0
            reasons.append("pr_number_invalid")

        grant: AuthorityGrant | None = None
        raw_grant = payload.get("grant")
        if not isinstance(raw_grant, dict):
            reasons.append("grant_missing")
        else:
            try:
                grant = AuthorityGrant.from_dict(raw_grant)
            except (KeyError, TypeError, ValueError):
                reasons.append("grant_malformed")

        at = time.time() if now is None else float(now)
        context = payload.get("context", {})
        if not isinstance(context, dict):
            context = {}
            reasons.append("context_invalid")

        if grant is not None and actor and repository and action in ACTION_MIN_ROLE:
            reasons.extend(self._verify_grant(grant, actor=actor, repository=repository, action=action, now=at))
        if action == Action.MERGE.value:
            reasons.extend(self._merge_preconditions(context))
        elif action == Action.FORCE_PUSH.value:
            reasons.extend(self._force_push_preconditions(context))

        decision = Decision.REFUSE if reasons else Decision.ALLOW
        if not reasons:
            reasons = ["authority_verified"]
        body = {
            "schema": "glaciereq.pr-authority-matrix.v1",
            "subject_id": req.subject_id,
            "actor": actor,
            "repository": repository,
            "pr_number": pr_number,
            "action": action,
            "grant_id": grant.grant_id if grant else None,
            "context": context,
            "decision": decision.value,
            "reasons": reasons,
        }
        return PrAuthorityMatrixReceipt(
            decision=decision,
            reasons=tuple(reasons),
            digest=_digest(body),
            metrics={
                "pr_number": pr_number,
                "required_role": ACTION_MIN_ROLE.get(action),
                "grant_ttl_remaining_s": max(0.0, grant.not_after - at) if grant else None,
                "revocation_count": len(self._revoked),
            },
            grant_id=grant.grant_id if grant else None,
            action=action or None,
            repository=repository or None,
            actor=actor or None,
        )

    def dispatch(
        self,
        req: PrAuthorityMatrixRequest,
        executor: Callable[[str, str, int, dict[str, Any]], Any],
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Authorize first and return a structured receipt for execution success or failure."""
        authority = self.evaluate(req, now=now)
        attempted = False
        executed = False
        result: Any = None
        error: dict[str, str] | None = None
        if authority.decision is Decision.ALLOW:
            attempted = True
            payload = req.payload
            try:
                result = executor(
                    str(payload["action"]).lower(),
                    str(payload["repository"]),
                    int(payload["pr_number"]),
                    dict(payload.get("side_effect", {})),
                )
                executed = True
            except Exception as exc:
                error = {"type": type(exc).__name__, "message": str(exc)[:500]}

        dispatch_receipt = {
            "authority": authority.as_dict(),
            "attempted": attempted,
            "executed": executed,
            "outcome": "EXECUTED" if executed else ("EXECUTOR_ERROR" if attempted else "REFUSED"),
            "result": result,
            "error": error,
        }
        dispatch_receipt["digest"] = _digest(dispatch_receipt)
        return dispatch_receipt


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, action: str, repository: str, pr_number: int, data: dict[str, Any]) -> dict[str, Any]:
        call = {"action": action, "repository": repository, "pr_number": pr_number, "data": data}
        self.calls.append(call)
        return {"ok": True, **call}


class GitHubRestExecutor:
    """GitHub REST executor for normal PR operations; raw force-push is separate."""

    def __init__(self, token: str, api_root: str = "https://api.github.com") -> None:
        if not str(token).strip():
            raise ValueError("github_token_required")
        self._token = token
        self._api_root = api_root.rstrip("/")

    def _request(self, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self._api_root + path,
            data=_canonical(body),
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "glaciereq-pr-authority-matrix",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                return json.loads(raw.decode("utf-8")) if raw else {"ok": True, "status": response.status}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"github_http_{exc.code}: {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"github_transport_error: {exc.reason}") from exc

    def __call__(self, action: str, repository: str, pr_number: int, data: dict[str, Any]) -> dict[str, Any]:
        repo_path = "/repos/" + repository
        if action == Action.LABEL.value:
            labels = data.get("labels", [])
            if not isinstance(labels, list) or not labels:
                raise ValueError("labels_required")
            return self._request("POST", f"{repo_path}/issues/{pr_number}/labels", {"labels": labels})
        if action == Action.COMMENT.value:
            body = str(data.get("body", "")).strip()
            if not body:
                raise ValueError("comment_body_required")
            return self._request("POST", f"{repo_path}/issues/{pr_number}/comments", {"body": body})
        if action == Action.REQUEST_REVIEW.value:
            reviewers = data.get("reviewers", [])
            teams = data.get("team_reviewers", [])
            if not reviewers and not teams:
                raise ValueError("reviewer_required")
            return self._request("POST", f"{repo_path}/pulls/{pr_number}/requested_reviewers", {"reviewers": reviewers, "team_reviewers": teams})
        if action == Action.UPDATE_BRANCH.value:
            body = {"expected_head_sha": str(data["expected_head_sha"])} if data.get("expected_head_sha") else {}
            return self._request("PUT", f"{repo_path}/pulls/{pr_number}/update-branch", body)
        if action == Action.MERGE.value:
            body = {k: data[k] for k in ("commit_title", "commit_message", "sha", "merge_method") if data.get(k) is not None}
            return self._request("PUT", f"{repo_path}/pulls/{pr_number}/merge", body)
        if action == Action.FORCE_PUSH.value:
            raise ValueError("force_push_requires_separate_executor")
        raise ValueError("unsupported_action")


Mechanism = PrAuthorityMatrix
