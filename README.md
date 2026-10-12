# webos-pyquirks

**A Python compatibility layer for LG webOS.**

`webos-pyquirks` aims to bring the Python 2.7.3 environment on LG webOS closer to a standard Linux CPython installation without modifying, replacing, or rebuilding the system interpreter.

It provides missing standard-library modules and compatibility patches to make existing Python code and third-party libraries work in the restricted webOS environment.

The project is designed to be lightweight, project-local, and easy to integrate.

## Features

* **No interpreter modifications** - works with the existing system Python.
* **Missing modules** - restores functionality that may be absent from the webOS Python build.
* **Compatibility patches** - applies patches at runtime through a bootstrap script.
* **Project-local setup** - keep compatibility modules alongside your project.
* **Incremental development** - modules and patches can be added as new compatibility issues are discovered.

## Requirements

* LG webOS with Python 2.7.3
* A copy of this repository
* Required system libraries for modules that depend on native functionality

`webos-pyquirks` does not replace the system interpreter or guarantee complete compatibility with every standard Linux Python installation.

## Installation

Add the repository to your project as a Git submodule:

```bash
git submodule add https://github.com/BrightCat14/webos-pyquirks.git webos-pyquirks
```

## Usage

Execute `bootstrap.py` at the beginning of your script, before importing modules that require compatibility support.

```python
import os

quirks_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "webos-pyquirks"
)

bootstrap_path = os.path.join(quirks_dir, "bootstrap.py")

exec(
    open(bootstrap_path, "r").read(),
    {
        "__file__": bootstrap_path,
        "__name__": "__main__"
    }
)
```

The bootstrap script adds the compatibility modules to Python's module search path and executes the available patches.

After initialization, import modules normally:

```python
import fcntl
import subprocess
import json
```

The modules available depend on the current version of `webos-pyquirks` and the capabilities of the underlying webOS system.

## How it works

`webos-pyquirks` operates entirely at the Python level wherever possible.

Its compatibility layer consists of:

* `modules/` - additional or replacement Python modules.
* `patches/` - runtime patches applied by the bootstrap script.
* `bootstrap.py` - initializes the compatibility layer.

Some functionality may still depend on the underlying kernel, C library, native extensions, or system libraries. Python-level compatibility cannot reproduce every feature of a standard Linux environment.

## Compatibility status

The project is under active development. Compatibility is tested directly on the target webOS environment using an audit script that checks module availability and functional behavior.

Not every missing standard-library module is implemented yet, and successful imports do not necessarily imply full API compatibility.

## Contributing

Contributions and bug reports are welcome.

When reporting a compatibility issue, include:

* The Python version and webOS version.
* The module or functionality that fails.
* The error message or relevant traceback.
* A minimal reproduction, if possible.
