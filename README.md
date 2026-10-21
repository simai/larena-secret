# Larena Secret

Secret broker for SecretReference, vault adapters, scoped leases, redaction, rotation and audited runtime access.

## Status

- **Contracts:** `SecretBroker`, `SecretLease`, `SecretReference`, `VaultAdapter` and the lease status and redaction
  enums. Interfaces only; no broker or vault runtime yet.
- **Data key wrapping: implemented.** Envelope encryption for storage field encryption: storages keep their own
  random 32-byte data keys (DEKs) only in wrapped form, and this package wraps and unwraps them.

Canonical specifications are in `simai/larena-specs` (`docs/specifications/packages/secret-package-tz.md`; plan
`docs/architecture/2026-10-22-storage-field-encryption.md`).

## Data key wrapping

`Larena\Secret\Contracts\DataKeyWrapper`:

| Method | Does |
| --- | --- |
| `wrap(string $dek, string $aad): WrappedDataKey` | Wraps a 32-byte DEK with the current KEK; the AAD is bound as is. |
| `unwrap(WrappedDataKey $wrapped, string $aad): string` | Returns the DEK; picks the KEK by `kekId` among the current and previous ones. |
| `currentKekId(): string` | The KEK id new wraps carry. A wrapped key with another id needs a rewrap after rotation. |
| `canUnwrap(WrappedDataKey $wrapped): bool` | Whether that KEK is known. It does not check the AAD or the ciphertext. |

`Larena\Secret\ValueObjects\WrappedDataKey` holds `kekId`, `algorithm` (`xc20p`), `nonce` (24 bytes) and
`ciphertext` (binary). `toArray()` and `fromArray()` use the keys `kek_id`, `algorithm`, `nonce`, `ciphertext`, with
unpadded base64url for the binary fields. `fromArray()` refuses any other shape.

### Local key policy

`Larena\Secret\Local\AppKeyDerivedDataKeyWrapper` resolves the TZ open decision «local encrypted adapter key policy»:

- **KEK:** `hash_hkdf('sha256', <raw APP_KEY>, 32, 'larena/secret/kek:v1')`. The purpose label is data; a different
  label derives an unrelated KEK.
- **KEK id:** `'app:' . first 16 hex of hash_hmac('sha256', 'larena/secret/kek-id:v1', <raw APP_KEY>)`. It is stable
  for a key and reveals nothing about the KEK.
- **Cipher:** XChaCha20-Poly1305-IETF (ext-sodium) with a random 24-byte nonce per wrap.
- **Keys:** the constructor takes the current APP_KEY (Laravel `base64:…` form or a raw string of at least 16 bytes)
  and the previous keys (`APP_PREVIOUS_KEYS`). New wraps use the current key; previous keys only unwrap.
- **Hygiene:** key parameters are `#[\SensitiveParameter]`; raw key material is wiped with `sodium_memzero` where PHP
  allows; the wrapper cannot be serialized, and its debug output lists KEK ids only.

The core classes have no framework dependency.

### Errors

Every failure throws `Larena\Secret\Exceptions\DataKeyUnavailable`. Its message and `reasonCode` hold a reason code
only. It never chains the original exception and never carries key material.

| Reason code | When |
| --- | --- |
| `secret_kek_unavailable` | Empty or invalid APP_KEY or previous key, or ext-sodium missing. |
| `secret_data_key_unwrap_failed` | Authentication failed: wrong KEK, tampered nonce or ciphertext, or a different AAD. |
| `secret_data_key_kek_unknown` | The wrapped key names a KEK that is neither current nor previous. |
| `secret_data_key_invalid` | The DEK is not 32 bytes, or the wrapped key has the wrong shape. |

### Binding (storage)

This package ships no service provider. The consumer (`larena/storage`) binds the wrapper lazily, so a missing
APP_KEY fails only the encryption paths:

```php
$this->app->singleton(DataKeyWrapper::class, static fn ($app) => new AppKeyDerivedDataKeyWrapper(
    (string) $app['config']->get('app.key'),
    array_values((array) $app['config']->get('app.previous_keys', [])),
));
```

The consumer then:

- generates DEKs with `random_bytes(32)`;
- stores `WrappedDataKey::toArray()` and the KEK id with each DEK;
- uses an AAD that names the storage and the DEK id;
- rewraps every DEK whose `kekId` differs from `currentKekId()` after a KEK rotation;
- refuses writes and imports before any change when the wrapper throws `secret_kek_unavailable`.

## Quality gate

```sh
PATH="/opt/homebrew/opt/php@8.3/bin:$PATH" composer run quality:gate
```
