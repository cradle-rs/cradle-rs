# Command Line Options

`cradle`'s primary subcommands are `serve`, `ctl`, and `dump`. Running
`cradle --help` (or `--help` on any subcommand) prints the authoritative list;
this chapter explains what each option does.

```
cradle serve [--config <FILE>] [--grpc <ENDPOINT>] [--pid-file <PATH>]
cradle ctl   [--grpc <ENDPOINT>]  <apply <FILE> | stats>
cradle dump  [--grpc <ENDPOINT>] [--vrf <ID>] [--no-resolve]  <l2|ipv4|ipv6|mpls|srv6>
```

## `cradle serve`

Loads the eBPF data plane, then optionally applies a bootstrap config and
serves the gRPC control API.

| Option | Short | Argument | Purpose |
|---|---|---|---|
| `--config` | `-c` | `FILE` | Bootstrap JSON config applied in-process at startup. |
| `--grpc` | `-g` | `ENDPOINT` | Serve the gRPC control API on this endpoint. Defaults to `unix:cradle/grpc`. |
| `--pid-file` | | `PATH` | Write this process's PID to `PATH` at startup. |

### `-c`, `--config FILE`

A JSON configuration applied once at startup, before the control API begins
serving. It describes ports, routes, services, and L7 services; see
[Configuration Model](ch-01-00-configuration.md). Omitting it starts an empty
data plane that can still be programmed over gRPC.

### `-g`, `--grpc ENDPOINT`

Serves the gRPC control API — the seam the zebra-rs `FibHandle` backend drives,
and the endpoint `cradle ctl` connects to. Defaults to `unix:cradle/grpc`, so
`serve` serves the control API even when `--grpc` is omitted. Four address forms
are accepted:

- `unix:NAME` — a Linux **abstract** socket (no leading `/`), scoped to the
  network namespace. The default `unix:cradle/grpc` is this form: it needs no
  filesystem path and is unique per netns, so per-namespace daemons don't
  collide.
- `unix:/path/to.sock` — a filesystem unix-domain socket. A stale socket file at
  that path is removed first.
- `tcp:HOST:PORT` — a TCP endpoint.
- a bare `HOST:PORT` — treated as TCP.

Several daemons in the **same** network namespace need distinct endpoints;
per-namespace daemons (the usual test layout) can all keep the default.

### `--pid-file PATH`

Writes the process ID to `PATH` immediately at startup. This is what the test
harness uses to locate and stop a backgrounded `cradle`.

## `cradle ctl`

The control-plane client. It connects to a running `cradle` over gRPC and
replays operations — the same operations the in-process bootstrap performs,
exercised across the wire.

| Option | Short | Argument | Purpose |
|---|---|---|---|
| `--grpc` | `-g` | `ENDPOINT` | The server endpoint to connect to (same forms as above). Defaults to `unix:cradle/grpc`. |

### `ctl apply FILE`

Loads a JSON config and replays it as gRPC calls against the server. Equivalent
in effect to having passed the same file to `serve --config`, but against an
already-running daemon.

### `ctl stats`

Fetches and prints the datapath packet counters — one line per counter, `name`
and `packets`. See [Observability and Counters](ch-03-01-observability.md).

```sh
cradle ctl stats
```

## `cradle dump`

Streams the contents of a single forwarding table from a running `cradle` over
gRPC and prints them in aligned columns. It is the per-entry counterpart to `ctl
stats`: where `stats` reports *how many* packets each layer handled, `dump` shows
you the table entries that drove those decisions.

| Option | Short | Argument | Purpose |
|---|---|---|---|
| `--grpc` | `-g` | `ENDPOINT` | The server endpoint to connect to (same forms as above). Defaults to `unix:cradle/grpc`. |
| `--vrf` | | `ID` | For `ipv4`/`ipv6`, dump this VRF table instead of the global one (`0` = global). Ignored for the other tables. |
| `--no-resolve` | | | Print raw nexthop ids instead of resolving each to its gateway / oif / label stack. |

The single positional argument selects the table:

| Table | Backing map(s) | Columns |
|---|---|---|
| `l2` | FDB | `mac vlan oif flags age_ms remote_sid` |
| `ipv4` | FIB4 (LPM or DIR-24-8) | `prefix vrf nh_id flags nexthop` |
| `ipv6` | FIB6 | same columns as `ipv4` |
| `mpls` | MPLS ILM | `label op nh_id vrf nexthop` |
| `srv6` | SRV6_LOCALSID + SRV6_ENCAP | local SIDs (My-SID) then transit encaps |

By default each entry's `nexthop_id` is resolved against the `NEXTHOPS` map and
printed as `via <gateway> dev if<oif> [labels …]`; `--no-resolve` skips that
lookup and prints the bare id (and avoids the extra map reads).

```sh
cradle dump ipv4
cradle dump ipv4 --vrf 10
cradle dump mpls
cradle dump srv6 --no-resolve
```

The `op` column of `dump mpls` reports the **effective** operation, so a
penultimate/ultimate-hop pop reads as `pop` even though cradle stores it as a
swap — see [Observability and Counters](ch-03-01-observability.md) for why.
