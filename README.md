# HP2.5_SHELL — EXPERIMENTAL GOVERNANCE SPIKE

This public repository is currently used only by:

HP25-PUBLIC-PROTECTED-GOVERNANCE-SHELL-SPIKE-001

Purpose: test whether a public GitHub repository can serve as a mechanically protected approval / trust anchor for HP2.5 without publishing private source code.

## Important non-claims

- Scheme C has NOT passed merely because this repository exists.
- This is NOT the HP2.5 Runtime, Control Plane, Wake-Up Plane, or production shell.
- ROOT-F-001 is NOT closed by this repository's existence.
- Approval records are meaningful only after server-side protection and gate behavior are mechanically verified.

## Public-data rule

This repository must contain governance metadata and synthetic spike fixtures only. Do not publish private source code, private patches, prompts, user content, credentials, tokens, cookies, passwords, or secrets.

## Trust model under test

A protected canonical approval record may point to an exact immutable source repository identity + 40-character commit SHA. A newer engineering HEAD does not automatically become approved.
