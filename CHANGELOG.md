# Changelog

## Unreleased

### Added

- `DataKeyWrapper` contract, `WrappedDataKey` value object and `DataKeyUnavailable` reason-code exception.
- `AppKeyDerivedDataKeyWrapper`, the local key policy: the KEK is derived from APP_KEY with HKDF-SHA256 and the label
  `larena/secret/kek:v1`, and wraps 32-byte data keys with XChaCha20-Poly1305. Previous APP_KEYs keep unwrapping
  after rotation.
- Tests for HKDF determinism, purpose separation, round trip, rotation, tamper rejection, fail-closed keys and
  exceptions without key material.

### Changed

- Requires `ext-sodium`.
