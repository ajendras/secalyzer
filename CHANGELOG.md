# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-09

### Added

- 20+ Rules — Detects XSS, SQLi, unsafe deserialization, weak randomness and signing bypasses.
- AST Analysis — Uses nikic/php-parser to understand code structure instead of regex.
- LLM Assistant — Sends focused snippets to OpenAI for contextual security review when API key provided.
- Fix Suggestions — Outputs ready-to-apply patches and secure alternatives for each finding.
- CMS Mode — Special rules for plugin/theme isolation, signed updates and client-site patterns.
- Beautiful Output — Color-coded terminal tables, severity gauges and one-click HTML reports.
- Multiple Formats — Exports JSON, SARIF for GitHub or self-contained HTML reports.
- Configurable — Ignore paths, set severity thresholds and load custom rules from JSON.
