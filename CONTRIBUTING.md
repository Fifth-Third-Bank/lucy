# Contributing to This Project

Thank you for your interest in contributing to LUCY! Because this codebase is maintained within a regulated banking environment, we operate with stricter security controls than most open-source projects. Please read the guidelines below before interacting with the repository.

## 🚫 Pull Requests Are Not Accepted

Due to internal security policies, **we do not accept external pull requests**. If you would like to help improve the project, please open an issue instead (details below).

All code changes are handled by the project maintainers.

## 🐛 Reporting Bugs

**Issues are welcome.** If you encounter unexpected behavior while using LUCY:

1. **Open an Issue** on GitHub using the bug report template.
2. Include the following to help us reproduce the problem:

### Required Details

- **Steps to reproduce** (the exact `lucy` command line, minus any private paths)
- **Expected vs. actual behavior**
- **Environment details**, such as:
  - LUCY version or commit
  - Claude Code version (`claude --version`)
  - Python version and operating system
- **Run evidence** where relevant:
  - the final verdict line (`REVIEW-COMPLETE ... CERTIFIED` / `PROCESS-COMPLETE`)
  - the failing gate check named in the output (e.g. `C2 QUIET`)
  - the last few `[lucy +Nm]` progress lines or a `--log` excerpt

### ⚠️ Never Include in an Issue

- Vulnerability findings from your own scans, code excerpts from scanned
  repositories, or scan reports - these describe weaknesses in *your*
  applications and do not belong in a public tracker.
- Secrets, credentials, API keys, or receipts/artifacts that may contain
  internal paths or identifiers. Sanitize before posting.

## 💡 Ideas and Feature Requests

Enhancement proposals are welcome as issues - new sweeps, lenses, detector
batteries, host integrations, and methodology critiques (canary design,
capture-recapture assumptions, court verdict law) are all fair game. LUCY is
open-sourced precisely to have its method inspected and challenged.

## 🔐 Reporting Security Vulnerabilities

**Do NOT open a GitHub issue for security concerns - in LUCY itself or found by it.**

If you believe you have discovered a security vulnerability in this project:

1. **Follow the disclosure process described in our [`SECURITY.md`](./SECURITY.md).**
2. Submit the report directly and privately using the channels listed there.

This ensures vulnerabilities are handled responsibly and do not put users at risk.

## 🙌 Questions & Discussion

If you have questions about using LUCY, feel free to open an issue for
clarification or discussion - even if it's not a bug. Just note in the issue
title that it's a question.

## 💬 Thank You!

We appreciate your interest and your effort to help improve the project.
Your reports and feedback make this project more useful and more secure for everyone.
