# Smoke

Status: `passed_static_only`

Smoke targets:

- Composer metadata validates with the `ext-sodium` requirement.
- New classes load through Composer autoload.
- Package tests pass, including the wrapper and value object tests.
- Scope checker accepts only launch-context files and this evidence path.

Result:

All smoke targets passed through the package-local quality gate. No runtime binding exists yet; storage (slice 3)
binds the wrapper.
