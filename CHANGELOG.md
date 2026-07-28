# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial release.

### Changed

- Resource and issuer identifiers are never rewritten (RFC 8414 §3.3 / RFC 9728 §3.3 require the
  advertised value to be *identical* to the configured one). `ProtectedResourceMetadata.wellKnownUrl`
  / `wellKnownPath` and the RFC 8414 metadata URL are formed by pure insertion, preserving the
  identifier's path exactly — including any trailing slash — and AS-metadata issuer comparison is now
  an exact string match. Identifiers are validated at construction (absolute http(s) URI with an
  authority and no fragment) and throw `IllegalArgumentException` otherwise; trailing slashes, host
  case, and explicit ports are legal and preserved. **Migration**: if your configured issuer or
  resource differs from your authorization server's actual identifier by a trailing slash, correct
  the config — the SDK no longer silently reconciles them.

### Fixed

- A configured issuer whose identifier legitimately ends in `/` no longer has every token rejected.
  The trailing slash was silently stripped at client construction and the stripped value compared
  against the token's `iss`, which RFC 9068 requires to carry the slash; discovery now also resolves
  the RFC 8414 well-known URL for such issuers correctly.
