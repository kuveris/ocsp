# Contributing

Thanks for looking. This is a small project, so the process is short.

## Before you start

For anything beyond a typo, open an issue first. It is a better use of your time
to find out the direction is wrong before you write the code rather than after.

Bug reports are more useful than most patches. If you hit something, a
reproduction — the config, the CA, what you expected, what you got — is genuinely
valuable.

## Development

Requires Go 1.25+ and, for linting, [golangci-lint](https://golangci-lint.run) v2.

```bash
make check    # lint + unit + integration, all under -race
make help     # every available target
```

`make check` is the gate — lint, unit, integration, and a coverage threshold.
If it fails, CI will fail too, because both run the same script with the same
number.

## Tests come first

Write the failing test, then the code that passes it. For a bug fix, that means
a test that reproduces the bug and fails before you touch anything else — it is
the only way to know the fix works and that the bug stays fixed.

Two conventions this project learned the hard way, both worth respecting:

**Do not encode test fixtures with the function under test.** The `GET` handler
accepted the wrong base64 alphabet for months because the tests encoded requests
with the same function the handler decoded them with. A symmetric test passes
whatever the implementation does. Where a format is defined by a spec, generate
fixtures with an independent tool and paste the result in.

**Do not assert against wall-clock elapsed time.** Compare against the value a
fixture was built with. A `time.Since(...) < someBound` assertion fails once the
suite runs longer than the bound, which makes the package impossible to stress
with `-count=N`.

## Commits

Format: `TYPE(scope): description`, or `ISSUE-ID (type): description` if you are
working from a tracked issue.

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `ci`, `perf`.

One logical change per commit. If your commit touches twenty files, it is
probably several commits.

## Changelog

User-visible changes get an entry under `[Unreleased]` in
[CHANGELOG.md](CHANGELOG.md) in the same commit as the change. Internal
refactors do not.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under the [MIT Licence](LICENSE). There is no CLA —
opening a pull request is taken as agreement that your contribution is licensed
under those terms.
