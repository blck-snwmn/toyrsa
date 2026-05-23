# toyaes
[![Go test&lint](https://github.com/blck-snwmn/toyrsa/actions/workflows/test.yaml/badge.svg)](https://github.com/blck-snwmn/toyrsa/actions/workflows/test.yaml)
[![CodeQL](https://github.com/blck-snwmn/toyrsa/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/blck-snwmn/toyrsa/actions/workflows/github-code-scanning/codeql)

Toy implementation of RSA written in Go.

## Development

CLI tools (`golangci-lint`, `lefthook`) are managed by [aqua](https://aquaproj.github.io/) with versions pinned in [aqua.yaml](aqua.yaml).

### Install tools

Install aqua itself first (see the [aqua installation guide](https://aquaproj.github.io/docs/install)), then install the pinned tools:

```bash
aqua install
```

### Set up git hooks

[lefthook](lefthook.yml) runs lint and test checks on staged `*.go` files before each commit. Register the hooks once after cloning:

```bash
lefthook install
```
