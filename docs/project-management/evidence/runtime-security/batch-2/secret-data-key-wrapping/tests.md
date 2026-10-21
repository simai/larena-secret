# Tests

Status: `passed`

Executed commands:

```bash
PATH=/opt/homebrew/opt/php@8.3/bin:$PATH /Applications/ServBay/package/bin/composer validate --strict
PATH=/opt/homebrew/opt/php@8.3/bin:$PATH /Applications/ServBay/package/bin/composer run quality:gate
git diff --check
```

Semantic checks (`tests/Unit/AppKeyDerivedDataKeyWrapperTest.php`, `tests/Unit/WrappedDataKeyTest.php`):

- HKDF determinism; the wrap opens with exactly HKDF-SHA256(raw key, 32, `larena/secret/kek:v1`);
- purpose separation: a different HKDF label derives a different KEK that cannot open the wrap;
- wrap/unwrap round trip, also through `toArray()`/`fromArray()` and a fresh instance;
- random nonce per wrap;
- rotation: the new APP_KEY wraps, the previous one unwraps, rewrap moves to the current KEK id;
- tamper rejected: nonce, ciphertext, tag, AAD, kekId swapped to another known KEK (`unwrap_failed`) or an unknown
  one (`kek_unknown`);
- data keys that are not 32 bytes rejected on wrap and unwrap;
- empty, invalid base64, short and non-string keys fail closed with `secret_kek_unavailable`;
- exceptions carry no key bytes: `var_export`/`print_r` of the exception and its trace args, with
  `zend.exception_ignore_args=0`, contain no raw key, APP_KEY, KEK or DEK in raw, hex or base64 form; no exception
  is chained. A mutation (dropping `#[\SensitiveParameter]` from the key parser) makes this test fail;
- the wrapper refuses serialization and its debug output lists KEK ids only;
- kekId follows the documented formula and is stable across instances and key forms;
- `WrappedDataKey` strict shape: algorithm, kek id, nonce and ciphertext lengths, extra/missing/non-string fields,
  padded or standard base64, bad alphabet.

Observed results: see the gate output recorded in the batch report.
