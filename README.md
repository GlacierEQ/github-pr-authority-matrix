# PR Authority Matrix

Independent GlacierEQ portfolio implementation aligned to public GitHub operating themes. This repository is not affiliated with or endorsed by GitHub.

## Purpose

Prevent automated or human pull-request side effects from bypassing explicit authority.

The matrix now implements the operational path the original repository only described:

1. issue a signed, short-lived grant bound to an actor, repository, roles, and allowed actions;
2. evaluate the requested PR action against the grant and runtime context;
3. refuse expired, revoked, tampered, borrowed, cross-repository, under-privileged, or ungranted authority;
4. enforce merge and protected-branch preconditions;
5. emit a deterministic decision receipt;
6. execute the side effect only after authorization.

## Supported actions

The authority model understands:

- `label`
- `comment`
- `request_review`
- `update_branch`
- `merge`
- `force_push`

The built-in GitHub REST executor implements the first five. `force_push` is intentionally left behind a separate executor boundary because raw ref mutation is materially different from normal PR operations; the matrix still evaluates whether such an action is authorized and whether protected-branch conditions permit it.

## Grant model

A grant is HMAC-signed and contains:

- grant id
- actor
- repository (or `*`)
- roles
- allowed actions
- issue time
- expiry time

The engine supports explicit revocation receipts and rejects altered MACs.

Role ordering is:

`read < triage < write < maintain < admin`

Action requirements are explicit in code. For example, merge requires `maintain`; force-push requires `admin`.

## Merge safety

A merge authorization also requires runtime context proving:

- the PR is not draft
- required checks passed
- required approvals are present
- the PR is not explicitly unmergeable

These are runtime invariants, not documentation gates.

## Run it

```bash
python scripts/operate.py
```

The command issues a demo grant, authorizes a label action, dispatches it through a recording executor, and prints the complete dispatch receipt.

## Real GitHub execution

`GitHubRestExecutor` uses GitHub's REST API and a caller-provided token. It supports labels, comments, reviewer requests, branch updates, and merges. No token is stored in the repository.

Typical application code constructs the matrix with its own secret, evaluates or dispatches a request, and provides a GitHub executor only at the actual side-effect boundary.

## Verify behavior

```bash
python -m pytest -q
```

Tests cover grant signing, expiry, revocation, actor/repository/action binding, role insufficiency, merge preconditions, dispatch refusal, protected-branch force-push policy, GitHub endpoint routing, and adversarial grant tampering.

## Current boundary

This is an operational authorization and dispatch library. It is not a GitHub App installation, hosted service, or claim of production deployment. Deployment belongs in the consuming control plane that owns secrets, repositories, and runtime identity.
