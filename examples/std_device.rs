//! A complete device on a std host, using the crate's batteries: `ureq` for the
//! transport, a directory for the storage, config from the environment or an
//! env file.
//!
//!     EXVISTA_DEPLOY_URL=… EXVISTA_DEPLOY_KEY=exd_… EXVISTA_DEPLOY_REPORT_URL=… \
//!         cargo run --example std_device -- ~/models/current
//!
//! Policy lives here, not in the crate. This example fails closed and does not
//! wait for the network; a real appliance retries transient errors for a while
//! after a cold boot (see `Error::is_transient`) before giving up.

use exvista_deploy::host::{DirStorage, UreqTransport};
use exvista_deploy::{Config, Device, Report, Sync};

fn main() {
    let dest = std::env::args().nth(1).unwrap_or_else(|| "./model".into());
    let Some(config) = Config::discover("/etc/exvista/device.env") else {
        eprintln!("not enrolled: set EXVISTA_DEPLOY_URL + EXVISTA_DEPLOY_KEY (or an env file)");
        std::process::exit(2);
    };
    let mut device = Device::new(config, UreqTransport::default(), DirStorage::new(&dest));

    let current = match device.sync() {
        Ok(Sync::Current(c)) => {
            println!(
                "current: {} (deployment {}) at {dest}",
                c.fingerprint, c.deployment_id
            );
            c
        }
        Ok(Sync::Staged(c)) => {
            println!(
                "staged:  {} (deployment {}) at {dest}",
                c.fingerprint, c.deployment_id
            );
            c
        }
        Ok(Sync::Nothing) => {
            eprintln!("refused: ExVista serves this device nothing");
            std::process::exit(3);
        }
        Ok(Sync::NoArtifact(served)) => {
            eprintln!("deployment {} carries no artifact", served.deployment_id);
            std::process::exit(3);
        }
        Err(e) => {
            eprintln!(
                "{e}{}",
                if e.is_transient() {
                    " (transient — retry)"
                } else {
                    ""
                }
            );
            std::process::exit(if e.is_transient() { 4 } else { 5 });
        }
    };

    // … load the model from `dest` here …

    if device.config().report_url.is_some() {
        match device.report(&Report::Loaded, Some(&current)) {
            Ok(()) => println!("reported loaded"),
            Err(e) => eprintln!("report failed: {e}"),
        }
    }
}
