# Issue contract — PR Authority Matrix

## Problem
Bot and human PR actions blur who may merge, label, or force-push under policy.

## Desired outcome
A bounded, open, testable implementation of **PR Authority Matrix** that demonstrates Dispatch PR side-effects only through an authority matrix with grant TTL and revoke receipts.

## Non-goals
- GitHub affiliation or proprietary integration
- Portfolio-wide scale/performance claims
- UI marketing site

## Acceptance
1. Mechanism module implements allow + refuse with structured receipts
2. pytest behavioral suite green
3. operate.py cold-start produces JSON receipt
4. Non-affiliation disclaimer preserved
