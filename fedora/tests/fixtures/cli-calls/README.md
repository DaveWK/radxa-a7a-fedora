# Fedora CLI inventory fixtures

The `.sh.fixture` files are input to the CLI scanner, not scripts to run.
The case arm and array command must be reported as unresolved calls, rather
than silently disappearing. The quoted `|` must stay in argv; argparse
must reject that call, including the trailing `--unexpected` option.

For argparse-based programs, the harness loads the target with `runpy`.
Imports and module-level code can run. The harness stops after argparse
parses the representative argv, before the selected CLI action runs.
It does not sandbox module initialization.
