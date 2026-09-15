# exvista_deploy

The device side of an [ExVista](https://www.exvistatechnologies.com) model
deployment: pull the model this device is cleared to run, verify it, stage it,
report it. Batteries included on a std host; a `no_std` core with two small
traits everywhere else.

```
                        ExVista                              your device
   deploy a model ───▶  scan · fingerprint · GATE
                              │ CLEAN → READY  ─────────────▶ pull → verify → stage → load
                              └ BACKDOORED → BLOCKED ───────▶ nothing served → don't start
```

A device physically cannot pull a blocked model. What this crate adds is the
part after the pull: the bytes are hashed as they stream, unzipped on the fly,
and only become the current checkpoint once the hash matched.

## On a std host: plug it in

```toml
[dependencies]
exvista_deploy = "0.2"
```

```rust
use exvista_deploy::{host::{DirStorage, UreqTransport}, Config, Device, Report, Sync};

let config = Config::discover("/etc/exvista/device.env").expect("not enrolled");
let mut device = Device::new(config, UreqTransport::default(), DirStorage::new("/opt/model"));

let current = match device.sync()? {
    Sync::Current(c) | Sync::Staged(c) => c,   // a verified checkpoint is at /opt/model
    Sync::Nothing => refuse_to_start(),        // the gate served nothing
    Sync::NoArtifact(served) => refuse_to_start(),
};
// … load the model …
device.report(&Report::Loaded, Some(&current))?;
```

That is the whole integration. `host::UreqTransport` is an HTTP client on
`ureq`, `host::DirStorage` stages into a sibling directory and renames it into
place atomically (the previous checkpoint survives until the rename succeeded),
and `Config::discover` reads `EXVISTA_DEPLOY_URL` / `EXVISTA_DEPLOY_KEY` /
`EXVISTA_DEPLOY_REPORT_URL` from the environment or a `KEY=VALUE` file.
[`examples/std_device.rs`](examples/std_device.rs) is a runnable version with a
fail-closed policy around it.

Swap either battery for your own by implementing the trait — a different HTTP
client, an object store, an A/B partition scheme — without touching the rest.

## Everywhere else: `no_std`, bring your own

```toml
[dependencies]
exvista_deploy = { version = "0.2", default-features = false }
```

The core is `no_std + alloc`: JSON, SHA-256, a streaming unzip, and the device
algorithm, with no network or filesystem code at all. You implement two traits
on your platform's primitives:

**`Transport`** — one small request/response (the pull and the report; return
*every* HTTP status as `Ok`, the crate decides what it means) and one streamed
`GET` of a presigned URL, fed to a sink in chunks.

**`Storage`** — a staging area driven like a transaction:

```text
current()     what is staged now, if anything intact
begin()       open a fresh staging area
  begin_entry("config.json") · write(..) · end_entry()
  begin_entry("model.safetensors") · write(..) … · end_entry()
commit(&cur)  the staged tree becomes THE checkpoint; record the markers
abort()       drop the staging area; whatever was current stays current
record(&cur)  same bytes redeployed under a new id: update the markers only
```

[`examples/embedded_traits.rs`](examples/embedded_traits.rs) shows both impls
written against only `core` + `alloc`, with every platform hook marked; it runs
on a host against in-memory fakes so the shape can be stepped through. On a
microcontroller the transport is your TLS stack (`reqwless`, a vendor SDK) and
the storage is two flash slots and a boot record.

CI builds the core for `thumbv7em-none-eabihf` on every push, so nothing with a
std dependency can sneak in.

## What the crate decides, on every target

- `Error` is an enum you act on without parsing strings: `Unauthorized`
  (key revoked), `NotProvisioned`, `Server`, `Transport`, `Integrity`,
  `Archive`, `NoArtifact`, … `Error::is_transient()` says what is worth
  retrying (no network yet, a 5xx) versus what is a decision.
- `files[].sha256` is checked over the raw download, incrementally; on a
  mismatch the staging area is aborted and nothing you had is touched.
- Zip entries are streamed, never buffered: STORED (what ExVista serves, zip64
  for multi-gigabyte weights) and DEFLATE. Entries that would escape the
  directory are refused. An archive with no files is refused — a marker must
  never vouch for an empty directory.
- The marker file names (`.exvista-fingerprint`, `.exvista-deployment`) are the
  ones every ExVista client uses, so a directory staged by the Python reference
  client reads as current here and vice versa.
- Known-value strings are enums (`Verdict`, `GateStatus`, `Report`), each with
  an `Other` escape hatch so a new server-side value never breaks a device.

**Policy is yours.** `Device::sync` never starts anything and never waits. Fail
closed or open, how long to retry after a cold boot, what `NoArtifact` means:
a few dozen lines on top, and they belong to the integrator. Two things every
integrator must handle: TLS needs a correct clock (a device that boots at 1970
must sync time before its first pull — the crate reports the failure as
transient), and the device key is the only secret, so keep it out of logs.

## Testing

```bash
cargo test                                          # core + std batteries (local HTTP mock, temp dirs)
cargo test --no-default-features                    # the core alone
cargo build --lib --no-default-features --target thumbv7em-none-eabihf   # the no_std check
cargo run --example embedded_traits                 # the bring-your-own shape, in memory
cargo run --example std_device -- ./model           # a real pull against your device key
```

## License

MIT.
