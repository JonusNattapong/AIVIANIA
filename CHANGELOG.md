# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.4] - 2025-10-15

### Added
- Body buffer middleware and helper for safely buffering request bodies (PR #3, PR #4).
- Security middleware and tests: CSRF protection, CORS handling, and security headers (PR #4).
- Observability improvements: Prometheus-style metrics and example (PR #1).
- CI: GitHub Actions workflow including format, clippy, cargo test, Docker build and Trivy image scan (PR #4).
- Local additions and example edits (PR #5).

### Merged PRs
- PR #5 - chore: upload local additions (merge commit: 5be3b69) — https://github.com/JonusNattapong/AIVIANIA/pull/5
- PR #4 - feat(body-buffer): add body buffer middleware, security tests, and CI (merge commit: 5c91b48) — https://github.com/JonusNattapong/AIVIANIA/pull/4
- PR #3 - feat(body): add request body buffering helper and middleware (merge commit: b13ba9a) — https://github.com/JonusNattapong/AIVIANIA/pull/3
- PR #2 - Feature/docker hardening (merge commit: a076b42) — https://github.com/JonusNattapong/AIVIANIA/pull/2
- PR #1 - feat(observability): add prometheus metrics, tracing init and example (merge commit: fe0c6e4) — https://github.com/JonusNattapong/AIVIANIA/pull/1

### Commits
- de87dc8 feat: local additions after merging main (metrics/example edits and other local changes)
- 5c91b48 Merge pull request #4 from JonusNattapong/feature/body-buffer
- dd29ad3 chore(tests): add security integration tests and backend shims; add CI workflow
- b13ba9a Merge pull request #3 from JonusNattapong/feature/body-buffer
- 4fbcabb feat(body): add request body buffering helper and middleware


For full details, see the GitHub PRs and commit history.
