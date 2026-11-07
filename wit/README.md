# WIT interface snapshot

`wabrix.wit` is generated from the canonical `wabrix_api` repository. The
upstream Git revision, SDK version, source path, and SHA-256 checksum are
recorded in `source.lock.json`. Commit the snapshot and lock file together.

Verify the committed snapshot without needing an SDK checkout:

```bash
python3 scripts/sync_wit.py --check
```

Compare it with the sibling SDK checkout, including its current WIT contents:

```bash
python3 scripts/sync_wit.py --check --source ../wabrix_api
```

After committing an interface change in the SDK repository, update the snapshot:

```bash
python3 scripts/sync_wit.py --source ../wabrix_api
```

Edit the canonical SDK interface first. The sync tool rejects uncommitted WIT
changes so every snapshot refers to an exact upstream revision. It requires
Python 3.11 or newer. Plugin builds read this local snapshot and require no
WIT downloads or paths into another repository.
