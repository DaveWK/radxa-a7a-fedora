# Fedora CLI inventory fixtures

The `.sh.fixture` files are input to the CLI scanner, not scripts to run.
The case arm and array command must be reported as unresolved calls, rather
than silently disappearing. The quoted `|` must stay in argv; argparse
must reject that call, including the trailing `--unexpected` option.

The substitution fixture must fail without guessing where a `#` starts a
comment. The two heredoc fixtures prove that `<<PY` inside Python source
does not open a heredoc, and that `END-PY` closes only on its full name.
In both cases the following invalid CLI call must reach argparse.

For argparse-based programs, the harness loads the target with `runpy`.
Imports and module-level code can run. The harness stops after argparse
parses the representative argv, before the selected CLI action runs.
It does not sandbox module initialization.

This is a conservative literal-reference inventory, not a shell interpreter.
It cannot discover targets assembled from fragments and run through `$cmd`.
Keep repository program names visible in source and add a line-specific,
reviewed argv sample when the inventory cannot safely recover a call.
