# exvista_deploy

The device side of an [ExVista](https://www.exvistatechnologies.com) model
deployment, as a `no_std + alloc` Rust crate. It knows the contract — pull,
compare, download, verify, commit, report — and nothing about your hardware.
You give it two things: a way to make HTTPS requests and a place to put files.

```
                        ExVista                              your device
   deploy a model ───▶  scan · fingerprint · GATE
                              │ CLEAN → READY  ─────────────▶ pull → verify → stage → load
                              └ BACKDOORED → BLOCKED ───────▶ nothing served → don't start
```

A device physically cannot pull a blocked model. What this crate adds is the
part after the pull: the bytes are hashed as they stream, unzipped on the fly,
and only become the current checkpoint once the hash matched.

## What you implement

Two traits. Both are small, both are blocking, and neither assumes an OS.

**`Transport`** — your HTTP client.

```rust
pub trait Transport {
    type Error;
    /// A small request/response (the pull, the report). Return EVERY HTTP status
    /// as Ok(Response); the crate decides what 401 / 404 / 409 / 5xx mean.
    fn exchange(&mut self, req: &Request) -> Result<Response, Self::Error>;
    /// GET a presigned URL and stream the body to `sink` in chunks. Artifacts can
    /// be gigabytes; never buffer the whole thing.
    fn download(&mut self, url: &str, sink: &mut dyn FnMut(&[u8]) -> Result<(), ()>)
        -> Result<(), DownloadError<Self::Error>>;
}
```

**`Storage`** — where the checkpoint lives, driven like a transaction.

```text
current()     what is staged now, if anything intact
begin()       open a fresh staging area
  begin_entry("config.json") · write(..) · end_entry()
  begin_entry("model.safetensors") · write(..) … · end_entry()
commit(&cur)  the staged tree becomes THE checkpoint; record the markers
abort()       drop the staging area; whatever was current stays current
record(&cur)  same bytes redeployed under a new id: update the markers only
```

On Linux that is a sibling directory renamed into place plus two marker files.
On a microcontroller it might be two flash slots and a boot record. See
[`examples/std_device.rs`](examples/std_device.rs) for a complete host
implementation on `ureq` + `std::fs` — about 150 lines, and the shape most
Linux appliances will want.

## What the crate does with them

```rust
let mut device = Device::new(config, my_transport, my_storage);

match device.sync()? {
    Sync::Nothing            => refuse_to_start(),         // the gate served nothing
    Sync::Current(c)         => load_and_run(&c),          // same bytes already staged, no download
    Sync::Staged(c)          => load_and_run(&c),          // downloaded, verified, committed
    Sync::NoArtifact(served) => decide_for_yourself(&served),
}
device.report(&Report::Loaded, Some(&current))?;           // provenance: this model is serving
```

`Error` is an enum you can act on without parsing strings, and
`Error::is_transient()` tells a policy what is worth retrying (no network yet,
a 5xx) versus what is a decision (key revoked, integrity failure, refused).

The crate never starts anything and never waits. **Policy is yours**: fail
closed or open, how long to retry a transient error after a cold boot, whether
`NoArtifact` means "resolve the model yourself" or "refuse". The reference
appliance policy — fail closed, retry transient failures for two minutes,
report `loaded` only once the server answers `/health` — is a few dozen lines
on top of `Device`.

## Verification, precisely

- `files[].sha256` is checked over the raw download, incrementally, and the
  staging area is aborted on mismatch. Nothing you had is touched.
- Zip entries are streamed, not buffered: STORED (what ExVista serves, zip64
  for multi-gigabyte weights) and DEFLATE (uploads). Entry names that would
  escape the directory are refused. An archive with no files is refused — a
  fingerprint marker must never vouch for an empty directory.
- The marker file names (`.exvista-fingerprint`, `.exvista-deployment`) are
  the ones every ExVista client uses, so a directory staged by the Python
  reference client reads as current to a Rust device and vice versa.

## `no_std`

The library has no `std` dependency at all: `serde_json` with `alloc`, `sha2`,
and `miniz_oxide` for inflate. CI builds it for `thumbv7em-none-eabihf` on
every push. Two things an embedded integrator owns:

1. **TLS and the clock.** ExVista's endpoints are HTTPS. A device that boots
   without a synced clock will fail certificate validation ("not yet valid");
   the crate reports that as a transient `Transport` error so your policy can
   wait for time sync and retry.
2. **Size.** Today's artifacts are checkpoint zips of hundreds of megabytes to
   gigabytes, streamed straight into storage. The crate keeps only one chunk
   plus a 32 KiB inflate buffer in memory, but the destination has to fit the
   model.

## Testing

```bash
cargo test                                      # contract + streaming zip, in-memory doubles
cargo build --lib --target thumbv7em-none-eabihf # the no_std check (rustup target add first)
cargo run --example std_device -- ./model        # a real pull against your device key
```

The in-memory `Transport` and `Storage` in [`tests/device.rs`](tests/device.rs)
are the smallest correct implementations of the traits — a good starting point
for a port.

## License

MIT.
