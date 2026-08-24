# Contributing to foca

Thanks for helping. Bug reports, ideas and pull requests are all welcome.

## Before you open a pull request

- For anything larger than a small fix, open an issue first, so we can agree on the
  approach before you spend time on it.
- Read [AGENTS.md](AGENTS.md), Part 2. It covers the ground rules (fail closed, keep trusted
  and untrusted data apart, secrets as zeroed `[]byte`), the layout, and how to build and
  test. [docs/design.md](docs/design.md) is the specification; a change that refines it
  updates it too.
- Run the checks the CI runs:

  ```sh
  nix develop
  gofmt -l internal cmd                # must print nothing
  go vet ./...
  go test ./...
  go test -tags foca_testing ./...
  ```

## License

foca is released under the [MIT License](LICENSE). By contributing, you agree that your
contributions are licensed under it too.
