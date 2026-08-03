# hsm-tool

CLI to work with key backed by HSM (AWS KMS, GCP KMS).

```
CLI tool for HSM or KMS

Usage: hsm-tool [OPTIONS] --cfg <CFG> <COMMAND>

Commands:
  hsm   HSM commands
  help  Print this message or the help of the given subcommand(s)

Options:
      --cfg <CFG>              Location of HSM config file, as default crypto provider where the key will be created
      --add-cfg <ADD_CFG>      Location of additional HSM config files
      --plain-key              Generate plain key using inmem provider
  -D, --debug                  Enable debug mode, the same as -l debug
  -l, --log-level <LOG_LEVEL>  Set the logging level (debug|info|warn|error) [default: error]
  -h, --help                   Print help

hsm commands:
  list      list keys
  info      print key information
  generate  generate key
  remove    delete key
```

Why multiple provider configs?

Imagine a Root CA key needs to be in one HSM while generating or signing another certificate with a key on another HSM or region (for AWS KMS, GCP KMS)
