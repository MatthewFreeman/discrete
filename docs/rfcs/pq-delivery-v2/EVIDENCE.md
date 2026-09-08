# Evidence and reproduction boundaries

This annex separates recorded experiments, calculations rechecked for the RFC,
and tests that require a future implementation. It is not a release certificate.
Public artifacts contain synthetic wallet data and no operator incident details,
wallet files, private production keys, local workstation paths or database copy.

## Measurements

Both experiments compare an exclusive legacy bound of 64 with 1. A bound of 1
still tries current-v2 and historical T0. Neither measures strict-v2 dispatch
after a consensus activation. p95 is nearest rank; there are 21 recorded samples
per policy after two warmups per policy, with alternating paired order.

| Workload and source | Wall median, 64 -> 1 | Wall p95, 64 -> 1 | Wallet CPU median, 64 -> 1 |
| --- | --- | --- | --- |
| Historical snapshot through a real local daemon/RPC; Core `ed4a27005bdaa211ff68bfb31f7bd1f7013c7771` | 3059.517 -> 1926.155 ms (1.588x) | 3459.741 -> 2234.055 ms | 2218.750 -> 1125.000 ms (1.972x) |
| Synthetic in-process WalletLegacy pipeline; Core `05cb1424ba9cea19bf3fa0630b647b9d6d9162cf` | 2040.906 -> 307.382 ms (6.640x) | 2156.786 -> 328.331 ms | 2031.250 -> 296.875 ms (6.842x) |

The smaller daemon-backed ratio is the important qualification of the synthetic
result: transport, parsing, daemon and non-scanner work remain. Do not sell
6.640x as the expected new-user or mainnet speedup. Nor does removing legacy
coverage from old history become correct merely because the benchmark is faster.

### Historical daemon-backed snapshot

The preserved [46-run CSV](evidence/daemon/warm-ab-21pairs.csv) contains four
warmup rows and 42 recorded rows. The [summary](evidence/daemon/summary.json)
and [analysis script](evidence/daemon/analyze_results.py) allow independent
recalculation. Those calculations were rerun before publication; the original
daemon experiment was not rerun as part of this docs-only PR.

The first daemon run was rejected because an atomic increment inside each
legacy trial added policy-dependent measurement overhead. The published data
comes from the rebuilt, full 21-pair repeat using one aggregate atomic counter
update per output on this miss path, rather than per trial. The discarded run
is not combined with these samples or used for the performance claim.

The recorded experiment used a frozen 14,804-block copied LMDB, top index 14803,
tip `4c39637697abc341c718b9adcfc623c7ad7ed8a74aaf32dfa09d814daa458fb3`,
through `WalletLegacy`, `BlockchainSynchronizer`, `WalletLedgerConsumer`,
`WalletLedger`, `NodeRpcProxy`, a localhost daemon and LMDB. Each timed run used
a fresh process and in-memory deterministic wallet, starting at zero and ending
at the synchronization-completed callback. The daemon remained at zero inbound
and outbound peers in the recorded before/after probes. This is a historical
snapshot, not a verified current network tip or a network-download benchmark.

The wallet owned no output in that snapshot. Both policies returned the same
recorded empty-wallet state, tip, 2,832 v2 attempts and 2,832 legacy-T0 attempts.
The instrumented baseline counted 178,416 nonzero-T trials (2,832 x 63); the
candidate counted zero. This does not establish equivalence for historical
wallets that do own legacy receipts. The [separate fixtures](evidence/daemon/fixture-results.jsonl)
show current-v2 recognition under both policies and the legacy-discovery loss.

All 21 recorded wall-time pairs favored bound 1. Warm filesystem cache, shared
host load, a single historical snapshot and an empty benchmark wallet limit
generalization. Recorded pre-run system CPU was 8.279% median / 14.073% max over
20 seconds; the host was not exclusive. The result excludes GUI interactions,
real owned history, controlled cold-cache pairs and current-tip synchronization.
The preserved manifest reports matching source/copy database hashes after clean
shutdown; this publication does not restart or inspect that daemon live.

Recorded source/build identity:

| Artifact | SHA-256 |
| --- | --- |
| Frozen LMDB | `b4dabc5731de383ed251c14fe508b13cc9a654d12ed194bdd466276fc98d88da` |
| Baseline bound-64 executable | `c9b957a2c9e25c726943185fcfc66198c670735b533d33f1463db9ea5e1de56f` |
| Candidate bound-1 executable | `f3a436bbb2bbabcc8573aaaabe1a865e5bbdf85eb6289f07779058a456e0f1e5` |

Host/build record: Windows 11, Ryzen 9 5900X, 24 logical CPUs, MSVC 19.44.35228,
static Release, CMake 3.31.8, Boost 1.86 and OpenSSL 3.5.3. Baseline and candidate
used the same instrumented source/build graph with a policy bound change.
The measurement includes instrumentation; it is not a cycle-accurate estimate
of an uninstrumented release. No peak-memory result is claimed.

The database and daemon-benchmark build/harness bundle are not distributed in
this RFC. Therefore this part is **reproducible statistical analysis of published
raw data**, not a self-contained replay of the exact historical experiment.
Independent integrated replay on a maintainer-owned snapshot remains a gate.

### Synthetic wallet pipeline

The [raw log](evidence/synthetic/ab-genesis-sync-4096-v2-outputs-release-final.txt)
and [CSV](evidence/synthetic/ab-genesis-sync-4096-v2-outputs-release-final.csv)
record 4,096 injected foreign v2 payment outputs and one owned v2 control
payment, in addition to generator-created base transactions: 67 blocks, tip 66.
The chain is immutable within the process, but randomized KEM/rho values mean a
new invocation constructs different bytes; the raw log pins that run's tip.

Each sample starts a fresh in-memory WalletLegacy from zero. The real wallet
pipeline runs through `INodeTrivialRefreshStub`, which bypasses full-node
consensus. All 42 recorded runs returned balance 800000, transaction count 1
and synchronized height 66. These are the checked state fields, not a claim of
byte-identical persisted wallet objects. Fixture construction is outside timing.

Wall time uses `steady_clock`; Windows process CPU uses checked `GetProcessTimes`
kernel plus user time. An earlier instrumentation error using MSVC `std::clock`
was corrected before the published final run; that function reports elapsed
wall time on MSVC, not process CPU ([Microsoft documentation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/clock?view=msvc-170)).
The final preflight recorded 9% CPU load; there was no continuous exclusive-host
guarantee. CPU accounting granularity is visible in the samples.

For isolated replay, apply [harness.patch](evidence/synthetic/harness.patch) to
a disposable Core checkout at `05cb1424ba9cea19bf3fa0630b647b9d6d9162cf`, build
`UnitTests` in Release following the repository build instructions, and use
[run_ab.ps1](evidence/synthetic/run_ab.ps1) with an explicit `-UnitTests` path
to that binary. The patch is benchmark-only, not a production default change;
the benchmark is disabled in ordinary unit-test runs. Do not apply it to a live
wallet checkout or connect it to a public daemon.

## Receiver tests

Recorded isolated tests at `05cb1424...` passed 13 scanner, seven builder,
16 derivation and ten review-only strict receiver cases: 46 total. The XML files
are in [evidence/tests](evidence/tests). The [review harness](evidence/receiver/README.md)
reuses the existing scanner's decryption and ownership predicates, omitting only
historical context fallback; it is not linked into the production build.

Current-output recognition preserves exact rho, amount, output index, context
and routing values relative to the compatible receiver. Foreign view keys,
wrong spend authority, payload/amount/commitment/index/input-hash mutations do
not credit. A later intact scan still succeeds. A historical-T0 vector is
accepted at bound 1 but rejected by strict-v2. The version-binding case tests
the signing digest, not node acceptance or signature validation for a new version.

The synthetic experiment's separate [wallet-regression XML](evidence/synthetic/wallet-sync-regression.xml)
records 42 passing cases, including current-format recovery, persistence,
detach/reorg and failure behavior. The 46 plus 42 sets contain 88 passing cases;
subset reruns are not counted again. They do not qualify future fork boundaries.

Both wallet experiments show the compatibility constraint:

| Effective bound | Historical T44 | Historical T259 |
| --- | --- | --- |
| 1 | Not discovered | Not discovered |
| 64 | Discovered | Not discovered |
| 260 | Discovered | Discovered |

The examples are synthetic routing cases. They are not evidence about any
operator's real payment, balance or wallet.

## Publication validation

`python verify_evidence.py` checks file hashes, sample counts, paired ordering,
reported medians/p95, the recorded state/counter invariants and XML case counts.
It does not replay Core, prove node validity, or turn data into a fork test.
The source commitments, scoped no-diff comparison and benchmark patch
applicability were checked before publication. No production source changes
are part of the RFC.

Remaining activation, historical-spend, recovery-metadata, parser, all-writer,
mempool/reorg and exact GUI gates are in the [RFC](README.md#validation-plan).
