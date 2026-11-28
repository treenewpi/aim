//! `aim-binderd --service NAME [--ready-file PATH]`
//!
//! Serves the binder driver under the bootstrap name NAME until killed.
//! Guests reach it with `linux-run --binder NAME`. `--ready-file` is written
//! after the daemon is checked in.

fn main() {
    let mut args = std::env::args().skip(1);
    let mut name = None;
    let mut ready = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--service" => name = args.next(),
            "--ready-file" => ready = args.next(),
            _ => {
                eprintln!("usage: aim-binderd --service NAME [--ready-file PATH]");
                std::process::exit(2);
            }
        }
    }
    let Some(name) = name else {
        eprintln!("usage: aim-binderd --service NAME [--ready-file PATH]");
        std::process::exit(2);
    };
    if let Err(e) = aim_binder_host::server::Server::start(&name) {
        eprintln!("aim-binderd: {e}");
        std::process::exit(1);
    }
    if let Some(path) = ready {
        if let Err(error) = std::fs::write(&path, b"ready\n") {
            eprintln!("aim-binderd: ready file {path}: {error}");
            std::process::exit(1);
        }
    }
    loop {
        std::thread::park();
    }
}
