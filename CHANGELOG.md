# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release.

### Changed

- Identifier handling now preserves issuer and resource identity. Issuers are stored and compared
  byte-for-byte (RFC 8414 §3.3) with no trailing-slash reconciliation; the terminating slash is
  stripped only when *deriving* a `.well-known` discovery URL (RFC 8414/9728 §3.1). The resource
  identifier is likewise preserved verbatim: deriving the Protected Resource Metadata path now
  strips the terminating slash of the resource path (`/mcp/` →
  `/.well-known/oauth-protected-resource/mcp`, RFC 9728 §3.1) without altering the resource
  identifier itself.

  **Migration:** If your configured issuer differs from your authorization server's actual
  identifier by a trailing slash, correct the config — the SDK no longer silently reconciles them.

### Fixed

- The derived Protected Resource Metadata URL now carries the resource identifier's authority
  verbatim. It was built from `URI.getAuthority()`, which percent-decodes, so an identifier whose
  userinfo contained an encoded `@` (`https://u%40b@api.example.com/mcp`) derived
  `https://u@b@api.example.com/…` — an authority with two `@` delimiters where the identifier
  names one. The raw authority is now used, matching the derived path, which already preserved
  its percent-encoded octets.
