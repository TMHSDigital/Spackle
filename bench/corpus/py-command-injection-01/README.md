# py-command-injection-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

The project parameter read in views.py is formatted into a command string in archive.py and executed with shell=True in runner.py.

## Planted

- `command-injection` (CWE-78) at `runner.py` line 16, sink `subprocess.run`: command string built in archive.py from the project and format parameters read in views.py

## Why this is a hard case

The taint crosses three files. views.py reads the parameter, archive.py turns it into a string, and runner.py executes whatever string it is given. The sink line in runner.py has no visible user input, and the string building in archive.py has no visible execution, so each file looks harmless when read alone.
