# Secret Data Key Wrapping Evidence

This evidence package records slice 2 of the storage field encryption plan for `larena/secret`: the KEK and the
data key wrapper.

Scope:

- plan: `docs/architecture/2026-10-22-storage-field-encryption.md` (larena-specs), «Keys» and slice 2
- package spec: `docs/specifications/packages/secret-package-tz.md`; resolves the open decision «local encrypted
  adapter key policy»
- feature: `secret.vault_adapter_contract`
- base commit: `259ec49410087624b0db30032d912705be3a22dd`

This batch does not persist keys, does not add a vault runtime adapter, a service provider, config, migrations,
routes or admin UI. Storage owns DEK generation, persistence and binding.
