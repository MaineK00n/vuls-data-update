# vuls-data-update

## Usage
```console
$ go run cmd/vuls-data-update/main.go -h
Fetch and Build data source

Usage:
  vuls-data-update [command]

Examples:
$ vuls-data-update fetch os
$ vuls-data-update fetch os debian
$ vuls-data-update fetch library
$ vuls-data-update fetch library cargo
$ vuls-data-update fetch other
$ vuls-data-update fetch other nvd
$ vuls-data-update build
$ vuls-data-update build nvd ubuntu


Available Commands:
  build       Build data source
  completion  Generate the autocompletion script for the specified shell
  fetch       Fetch data source
  help        Help about any command

Flags:
  -h, --help   help for vuls-data-update

Use "vuls-data-update [command] --help" for more information about a command.
```