# Dependency locks

`pyproject.toml` gives each dependency a range (a floor we have tested and the next major version as a ceiling).
These files give the exact versions that were tested and audited together. Use them as constraints, so a
fresh install gets the same code every time:

    pip install -c lock/runtime.txt '.[swarm,mcp,relay,fast]'     # a deployment
    pip install -c lock/dev.txt -e '.[swarm,mcp,relay,fast,dev]'  # development and tests

A constraints file limits versions without adding packages, so installing fewer extras is fine.

## Regenerating

    python3 -m venv /tmp/rt && /tmp/rt/bin/pip install -U pip pip-audit
    /tmp/rt/bin/pip install '.[swarm,mcp,relay,fast]'
    /tmp/rt/bin/pip freeze --exclude-editable --exclude torrenthub > new-runtime.txt
    /tmp/rt/bin/pip-audit

Do this on a schedule, not only when something breaks: a lock file keeps known-vulnerable versions
installed until someone updates it. Run the full suite on the new set before replacing the old one.

The locks carry versions, not hashes, and were built for CPython 3.12 on Linux x86_64. Other
platforms may resolve different wheels. Hash-pinned locks (`pip install --require-hashes`) would
also defend against a tampered package index; that is not done yet.
