# Tests

Status: `passed`

Executed commands:

```bash
PATH=/opt/homebrew/opt/php@8.3/bin:$PATH /Applications/ServBay/package/bin/composer validate --strict
PATH=/opt/homebrew/opt/php@8.3/bin:$PATH /Applications/ServBay/package/bin/composer dump-autoload
PATH=/opt/homebrew/opt/php@8.3/bin:$PATH /Applications/ServBay/package/bin/composer run quality:gate
git diff --check
git diff -U0 | rg -i "BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|xox[baprs]-|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}"
```

Semantic checks:

- consumer-visible value is SecretReference only;
- SecretReference does not expose raw-value style methods;
- lease contract carries actor, operation, provider, environment, expiration and
  redaction surface;
- denied and revoked leases fail closed;
- redaction levels do not expose sensitive material.

Observed results:

- `composer.json is valid`
- Composer autoload files generated successfully.
- `validate-larena-package`: `Larena Secret coding launch context is valid.`
- PHP lint checked scripts, tools, `src` and `tests` with no syntax errors.
- PHPStan analysed scripts, tools, `src` and `tests` with no errors.
- `SecretReferenceContractTest passed.`
- `SecretLeaseRedactionTest passed.`
- Evidence contract passed for the current repository state.
- Scope check passed for launch allowed files and evidence path.
- `git diff --check` passed.
- Narrow credential-pattern diff scan found no typical raw private key, cloud key
  or access token pattern.
