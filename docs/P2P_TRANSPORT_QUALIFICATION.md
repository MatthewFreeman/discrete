# PQ P2P transport qualification

Local qualification, 10 September 2026. Baseline:
`9fd5415ca5332b512b02dd091fc8d448c5c8b6b5` in `discretecoin/discrete`.

The candidate delivers native optional PQ transport for maintainer review.
R2 corrects a reproduced Windows fixture port collision and makes fixture waits
bounded. The results below distinguish current R2 checks from retained R1 cost
measurements. The release default stays `off`; platform release and network
activation are separate maintainer decisions.

## What was exercised

| Check | Direct result |
| --- | --- |
| Linux native TCP/TLS suite, R2 | 24/24, including duplex I/O, moves, cancellation, partial delivery, maximum Levin payload, policy rejection, key storage and admission |
| Linux UBSan native suite, R2 | 24/24 with undefined-behavior recovery disabled |
| Windows native TCP/TLS suite, R2 | 23/23 in each of three consecutive final runs on OpenSSL 3.5.8 |
| Windows fixture isolation, R2 | 60/60 dedicated listener/deadline/duplex cases; both concurrent 40-case runs completed without stalls or exchange failures; timing failures retained |
| Legacy-only build with OpenSSL 3.0.13 | Daemon built; 3/3 policy/unavailable-capability tests |
| Real old/new processes | Baseline server + mixed client, mixed server + baseline client, and required/required all passed |
| Full-node lifecycle | Core + LMDB initial sync; funded PQ transaction relay; block relay and mempool removal; restart, persisted-peer discovery and catch-up to height 16 |
| Real daemon CLI | Startup and separate key loading; invalid/unsupported modes rejected; 16 global / 4 per-source admission bounds, capacity reuse; shutdown exit 0 |
| Sustained record keys | 34 GiB of checked payload in 40.96 s; 33 sent and received KeyUpdates |
| Adjacent regressions | Linux System, PQ chain and PQ wallet suites passed; Windows PQ chain and wallet CTest targets passed 2/2 |

The one-test Linux/Windows count difference is the POSIX special-file key test.
Full-node tests use synthetic early upgrade heights and a public deterministic
test account. They do not use real funds or contact public peers. Linux fixtures
run in a network namespace with loopback only; three-node discovery includes a
seed advertising a different reachable node. Standalone daemon checks also run
inside that isolation.

Windows daemon compilation and `--help` succeeded. Full daemon networking was
not run on the host: the unchanged daemon startup includes UPnP port mapping.
Windows loopback stream tests do not invoke that daemon startup path.

## Cost, including the unfavorable result

Host: AMD Ryzen 9 5900X, x86-64 Windows/WSL2, Ubuntu 24.04, GCC 13.3,
Boost 1.83, release optimization. Baseline and candidate full-node measurements
use the same OpenSSL 3.5.8 build. A separate unchanged baseline with system
OpenSSL 3.0.13 supplies the adjacent regression comparison.

Retained R1 series: ten alternating comparative samples, 30 full-node runs, one frozen
13-block input. Every sample is retained, including timing outliers. The initial
chain tip is `6872e603502e329f1995ce2c1cd0db9c0eb3bf5898ebb70b5e9cb6f3af0065c2`.

| Metric, median | Unchanged baseline | Candidate `off` | Candidate `pq-required` |
| --- | ---: | ---: | ---: |
| Initial full-node sync | 102.273 ms | 102.761 ms | 111.989 ms |
| Funded transaction relay | 5.523 ms | 5.851 ms | 5.700 ms |
| Block construction + relay | 48.371 ms | 48.778 ms | 28.288 ms |
| Restart catch-up | 107.405 ms | 106.565 ms | 112.451 ms |
| Full fixture user / system CPU | 0.34 / 0.06 s | 0.33 / 0.06 s | 0.35 / 0.06 s |
| Full fixture peak RSS | 27,146 KiB | 30,338 KiB | 33,962 KiB |

The paired median initial-sync difference is **+6.935 ms / +7.04%** for PQ and
**+0.210 ms / +0.335%** for legacy. A median of paired differences is not the
difference between column medians. The lower PQ block-relay measurement does not
establish a general speedup; it includes mining and host scheduling noise.
RSS above covers two full nodes in one process, not a per-connection allocation.

| Native TCP-backed stream, 64 MiB | Candidate plaintext | Candidate PQ TLS |
| --- | ---: | ---: |
| Payload throughput, median | 1,196.27 MiB/s | 589.80 MiB/s |
| Transfer CPU, both endpoints combined | 0.05572 s | 0.10851 s |
| Connection setup, median | 0.0848 ms | 1.7322 ms |
| PQ setup p95, nearest-rank with 10 samples | — | 3.2868 ms |
| TLS handshake bytes, both directions | 0 | 8,219 bytes |

Encryption approximately halves this loopback capacity and doubles transfer CPU.
It is not free. The minimum observed PQ throughput was 405.22 MiB/s. The handshake
cost is paid per connection, not per block or transaction. IP addresses, timing,
volume and recognizable TLS remain visible.

Frozen engineering rejection thresholds were: paired legacy sync regression over
10% **and** 20 ms; PQ over 15% **and** 50 ms; local handshake p95 over 100 ms;
bulk below 100 MiB/s; and timer delay over 50 ms during 16 concurrent handshakes.
These are this host's qualification thresholds, not maintainer-approved SLOs.
The final comparative series passed its four timing/throughput gates. The earlier
ten-sample series is also retained: sync medians 93.998 / 91.325 / 96.021 ms and
PQ bulk 651.59 MiB/s, illustrating run-to-run variance.

The retained R1 native burst completed 16 handshakes while 16 established exchanges
made progress. Linux maximum timer delay was 1.283 ms; Windows full-run maxima
were 14.958, 15.309 and 15.188 ms. Linux RSS increased from 11,943,936 to 15,872,000
bytes across 32 additional TLS endpoints after warmup, about 120 KiB each.
The sampled peak equaled that retained value; this is not a worst-case allocator
or adversarial-memory proof. Windows RSS was not measured. Windows CPU counters
use `GetProcessTimes`; its coarse accounting is not suitable for interpreting
individual short handshakes. Earlier Windows fields named `burst_cpu_ms` used
MSVC's wall-time `clock()` and must not be interpreted as CPU measurements.

## Failure history and unresolved evidence

* An early transport revision achieved only about 20 MiB/s and materially slowed
  the node fixture. TLS record-tail fragmentation plus Nagle/delayed ACK was
  corrected with TLS-only TCP_NODELAY and bounded writes that include the record
  tail. Plaintext socket behavior was preserved. The final measurements above
  include that change.
* R2 reproduced a Windows stall on OpenSSL 3.5.8 when two test processes shared
  the fixed listener port. The stalled fixture was waiting in bare accept, before
  TLS. OS-assigned ports, bounded fixture waits and process-unique key paths correct
  this test defect. Both concurrent 40-case runs then completed without a stall or
  exchange failure; their scheduling assertions were not all green. The original
  two 3.5.3 stalls lack socket traces for individual retrospective attribution.
* The first full R2 Windows series passed 65/69 cases: three burst-delay failures
  and one fragmenting-proxy failure at 5.254 s. Proxy sockets now disable Nagle;
  113-byte fragments, the requested 1 ms pause and all production limits are
  unchanged. The final series is reported in the table. A separate Windows System
  run passed 134/136, failing two unchanged timer upper bounds without linking TLS.
  This establishes scheduling failures outside TLS, not unrestricted performance
  under load. All observations are retained in the R2 evidence.
* An exploratory Windows 100-repeat scheduling run, concurrent with other builds
  and tests, violated the 50 ms delay threshold. Its process-wide 60 s deadline
  stopped iteration 52. This was a failed loaded-host timing run, not evidence
  that 100 iterations passed or that the global timeout itself was a deadlock.
  Completed iterations still exchanged data. The threshold was not relaxed.
* Linux HTTP framing passed 10/11 on both unchanged baseline and candidate. The
  same existing timeout-floor assertion measured 149 ms against a 150 ms minimum;
  both four-target regression commands returned exit 8. That failure is retained,
  not reported as an all-green regression run. No unrelated timer patch is included.
* An early seed fixture lacked a second advertised peer and failed on both
  baseline and candidate. The corrected three-node fixture now checks actual
  discovery. Earlier dependency/build failures and the original observations
  remain in the local evidence history.

## Maintainer decisions and release conditions

Review the native owner/cancellation path, strict fallback policy, RPK pin/name
verification, pre-ready limits and KeyUpdate accounting. The dedicated Linux
workflow is included and its functional script was run locally; no hosted CI
result is claimed before publication. Windows/MSVC, MinGW, macOS and ARM release
artifacts need their own maintained-platform qualification. In particular, local
Windows stream passes are not full Windows daemon lifecycle qualification.

Before changing the default, qualify a representative long-running mixed network,
low-power hosts, reachable seeds and peer diversity. `pq-required` excludes old-only
peers by design. Merge of optional support and activation of a network default are
separate decisions; reverting the source does not require a chain/peer database
migration. Operators must explicitly remove incompatible secure policy settings
when choosing weaker legacy operation.

This is not an independent cryptographic audit, a performance comparison with
Quantus, an anonymity system or a guarantee against an unpinned active intermediary.
ML-DSA-65 authenticates possession of the server key; trusted identity additionally
requires the configured pin and name. KeyUpdate is not post-compromise recovery.
See [the operator guide](P2P_TRANSPORT.md) for exact guarantees and standards status.
