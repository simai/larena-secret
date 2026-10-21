# Implementation Summary

Status: `implemented_data_key_wrapping`

Added:

- `DataKeyWrapper` contract: `wrap`, `unwrap`, `currentKekId`, `canUnwrap`;
- `WrappedDataKey` value object (`kek_id`, `algorithm` = `xc20p`, `nonce`, `ciphertext`) with a strict
  unpadded-base64url array shape;
- `DataKeyUnavailable` exception with reason codes only (`secret_kek_unavailable`,
  `secret_data_key_unwrap_failed`, `secret_data_key_kek_unknown`, `secret_data_key_invalid`), never chained;
- `AppKeyDerivedDataKeyWrapper`: KEK = HKDF-SHA256(raw APP_KEY, 32, `larena/secret/kek:v1`); KEK id =
  `app:` + 16 hex of HMAC-SHA256(`larena/secret/kek-id:v1`, raw APP_KEY); XChaCha20-Poly1305-IETF with a random
  24-byte nonce; AAD passed through; previous APP_KEYs unwrap after rotation;
- `ext-sodium` requirement; README, CHANGELOG.

Key policy decision (TZ open decision «local encrypted adapter key policy»): the local KEK is derived from APP_KEY by
HKDF with a purpose label; data keys are wrapped by it. A dedicated or vault-backed KEK can replace it later by
rewrapping the DEKs only.

Not added:

- key or DEK persistence (storage owns `larena_storage_data_keys`);
- service provider or config (no provider pattern in this package; storage binds the wrapper lazily);
- vault runtime adapter, production secret resolution, admin UI, routes, migrations.
