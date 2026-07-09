# Command Line Options

`cradle` has two subcommands. Running `cradle --help`, `cradle serve --help`, or
`cradle ctl --help` prints the authoritative list; this chapter explains what
each option does.

```
cradle serve [--config <FILE>] [--grpc <ENDPOINT>] [--pid-file <PATH>]
cradle ctl   [--grpc <ENDPOINT>]  <apply <FILE> | stats>
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
