# fido2-bio

Add and list fingerprints on a FIDO2 device

The reason for the existence of this tool is that other tools
were not able to manage fingerprints on an eWBM security key.
This tool works for that device.

# Installation

```
poetry install
```

# Usage

List fingerprints:

```
poetry run python bio.py --list
```

Add a new fingerprint:

```
poetry run python bio.py --add
```

# Credits

Based on a python-fido2 example
