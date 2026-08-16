# Backup manifest before raw Tetragon correlation fix

The previous versions remain recoverable from Git history. Key blobs before this update:

- `app/main.py` — `75fb4416d83427f8907c7ff5cb3c844ff1e4bf8d`
- `app/models.py` — `671187cd338679aa052a2834f14a9769f28d7336`
- `app/tetragon.py` — `765399cffad7ff026685094e3406c556b079f685`
- `app/detector.py` — `09f563fe1f6ecea031c9293ec4502cfa8dcd0d07`
- `app/context.py` — `0d5f0f62de0647e3afb8bcd014b1813f9cb08ffa`
- `tetragon-adapter.py` — `d2e60488f343aef3bdc419eb15bc22469542debf`
- `collector/tetragon_collector.py` — `214666dc4bd3e77f889e73384e1a4957cc0b1d3f`

Use `git show <blob-sha>` or normal Git history to restore any previous implementation.
