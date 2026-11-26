# vuls-data-update

## Usage
```console
$ go install github.com/MaineK00n/vuls-data-update/cmd/vuls-data-update@nightly

$ vuls-data-update --help
Fetch and Extract data source, Operate vuls-data-* dotgit

Usage:
  vuls-data-update [command]

Examples:
$ vuls-data-update fetch debian-security-tracker-salsa
$ vuls-data-update extract debian-security-tracker-salsa vuls-data-raw-debian-security-tracker-salsa
$ vuls-data-update dotgit pull ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker-salsa


Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dotgit      Operate vuls-data-* dotgit
  extract     Extract data source
  fetch       Fetch data source
  help        Help about any command
  version     Print the version

Flags:
  -h, --help   help for vuls-data-update

Use "vuls-data-update [command] --help" for more information about a command.
```