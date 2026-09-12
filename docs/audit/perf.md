# Performance track — purepdb audit, 2026-09

Branch `perf/hot-paths`, worktree `/home/user/wt/perf`. Every number here is
from `tools/bench.py` (best of `--repeat 3`, wall seconds, CPython 3.11.15,
4-core Xeon @ 2.80 GHz) unless it says otherwise. Peak RSS is the process
high-water mark from `resource.getrusage`, so the column only rises.

Correctness gate for every change: the test suite, `ruff check`, `ty check`,
`tools/fuzz.py`, and `tools/snapshot.py` output diffed byte for byte against
the unmodified `main` checkout on every fixture and every corpus file.

## Baseline (main at e978f3a, before any change)

```
tests/data/sqlite/x64/sqlite3.pdb  (3.1 MB)
  op                 seconds     count   peak RSS MB
  open                 0.017        69          29.0
  functions            0.183      3601          30.1
  public_symbols       0.009       660          30.1
  diagnose             0.499         0          30.3
  lines                0.182     69834          71.3
  inline_sites         0.091         0          71.3
  labels               0.074      1237          71.3
  data_symbols         0.079       403          71.3
  total                1.135
tests/data/sqlite/x86/sqlite3.pdb  (3.1 MB)
  open                 0.006        78
  functions            0.181      3620
  public_symbols       0.009       685
  diagnose             0.502         0
  lines                0.186     70157
  inline_sites         0.089         0
  labels               0.074      1412
  data_symbols         0.079       481
  total                1.126
tests/data/rustpe/rust_pe_symbols_msvc.pdb  (0.8 MB)
  open                 0.004       161
  functions            0.033       399
  public_symbols       0.002       451
  diagnose             0.171         0
  lines                0.005      1807
  inline_sites         0.050      3797
  labels               0.014       160
  data_symbols         0.015         1
  total                0.294
```

(`lines` peak RSS is the `list()` in the bench holding 70k `Line` objects,
not the parser.)

### Baseline profile, sqlite x64, all operations once (cProfile, 4.8 s under
the profiler)

```
   ncalls  tottime  cumtime  filename:lineno(function)
   500597    0.980    3.507  codeview.py:498(iter_records)
  1034683    0.562    1.511  reader.py:37(u16)
  1730293    1.158    1.296  reader.py:27(_take)
   500037    0.169    0.547  reader.py:49(bytes)
  1001264    0.323    0.406  reader.py:21(remaining)
```

73% of all time is the record walk: one `Reader` per stream, two `u16()`
calls (each a slice plus `struct.unpack`), a `remaining()` and a `bytes()`
slice per record, and a `RawRecord` per record whether or not the caller
wants that kind. `diagnose()` walks each module stream four times
(`count_malformed_records` twice, `count_kinds`, then `module_procs()` and
`inline_sites()` again); `functions()` walks each module stream twice
(`module_procs()` and `thunks()`).
