//! One root for the property service, the original servicemanager, and the
//! original libbinder probe.
//!
//! The `android` and `libbinder` commands keep their own root and its
//! generated `servicemanager.ready=true` area. This root is a copy with
//! that area removed. The original servicemanager is what publishes
//! `servicemanager.ready`. The original `service` client is started first
//! and must still be waiting when servicemanager starts.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aim_binder_driver::absence::{parcel_reply, saw_return};

use super::manager::{copy_tree, manager_root};
use super::property::{
    self, emit_guest, finish, launch, opened, property_area, reclaim_owned_property_area,
    stderr_of, stdout_of, PropertyServer, READY, SERVICEMANAGER_IDENTITY, SHELL,
};
use super::{binder_device_opened, require_layer, set_mode, sha256_file};

const PING: &str = "dev.aim.ping";

pub fn integrated_root() -> PathBuf {
    super::stage_dir()
        .parent()
        .expect("redroid stage")
        .join("redroid-16-integrated")
        .join("root")
}

/// Copy the servicemanager root, delete its generated property area, and
/// add the original getprop/setprop symlinks. Does not write
/// `servicemanager.ready`.
pub fn prepare_integrated() -> Result<PathBuf, String> {
    let layer = require_layer()?;
    let source = manager_root();
    if !source.join("system/bin/servicemanager").is_file()
        || !source.join("system/bin/libbinder-ping").is_file()
    {
        return Err(
            "servicemanager root is not staged; run bionic-smoke --prepare-servicemanager first"
                .into(),
        );
    }
    let root = integrated_root();
    if root.exists() {
        fs::remove_dir_all(&root).map_err(|e| format!("remove {}: {e}", root.display()))?;
    }
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    copy_tree(&source, &root)?;
    set_mode(&root, 0o755)?;
    let seeded = property_area(&root);
    if seeded.exists() {
        fs::remove_dir_all(&seeded).map_err(|e| format!("remove {}: {e}", seeded.display()))?;
    }
    let owner = property::property_area_owner(&root);
    if owner.exists() {
        fs::remove_file(&owner).map_err(|e| format!("remove {}: {e}", owner.display()))?;
    }
    property::install_property_clients(&layer, &root)?;
    if property_area(&root).exists() {
        return Err("integrated root still has a property area".into());
    }
    let original = sha256_file(&source.join("system/bin/servicemanager"))?;
    let copied = sha256_file(&root.join("system/bin/servicemanager"))?;
    if original != copied {
        return Err("integrated servicemanager bytes differ from the regression root".into());
    }
    if !root.join("system/bin/getprop").is_file() || !root.join("system/lib64/libbinder_ndk.so").is_file()
    {
        return Err("integrated root is missing getprop or libbinder_ndk.so".into());
    }
    write_provenance(&root, &layer)?;
    println!(
        "bionic-smoke: integrated root {} has no seeded servicemanager.ready (staged, not executed)",
        root.display()
    );
    Ok(root)
}

fn write_provenance(root: &Path, layer: &Path) -> Result<(), String> {
    let text = format!(
        "kind original-servicemanager-and-property\n\
         layer {}\n\
         not_play_store true\n\
         not_redroid_boot true\n\
         copied_from redroid-16-servicemanager/root\n\
         seeded_servicemanager_ready_removed true\n\
         servicemanager_ready_not_seeded true\n\
         property_area_removed_when_server_stops true\n\
         seeded_area_without_owner_still_rejected true\n\
         android_and_libbinder_regression_roots_unchanged true\n\
         property_info_is_default_context_only true\n\
         acceptance_platform apple-silicon-macos-xnu\n\
         linux_stage_is_not_acceptance true\n\
         executed false\n",
        layer.display()
    );
    let path = root
        .parent()
        .ok_or("integrated root has no parent")?
        .join("provenance.txt");
    fs::write(path, text).map_err(|e| e.to_string())
}

/// `binder_name` is the daemon the caller already checked in. This process
/// serves the property socket. Guests are separate `linux-run` processes.
pub fn run_integrated(linux_run: &Path, binder_name: &str) -> Result<(), String> {
    property::print_host();
    println!("integrated original-servicemanager original-libbinder_ndk not-synthetic");
    println!("integrated binder={binder_name}");
    if !linux_run.is_file() {
        return Err(format!("linux-run is not a file at {}", linux_run.display()));
    }
    let root = integrated_root();
    if !root.join("system/bin/servicemanager").is_file() || !root.join("system/bin/getprop").is_file()
    {
        return Err(
            "integrated root is not staged; run bionic-smoke --prepare-integrated".into(),
        );
    }
    // A previous server may have been killed before Drop. Only an area
    // that server marked is removed. A seeded area has no mark and still
    // fails below, so this is not a manual clear of the assertion.
    reclaim_owned_property_area(&root)?;
    if property_area(&root).exists() {
        return blocker(
            "integrated root already had a property area",
            "the server must be the process that creates it",
        );
    }
    let server = PropertyServer::start(&root)?;
    if server.get(READY).is_some() {
        return blocker("ready was present at start", &server.log());
    }
    let mut before = launch(linux_run, &root, SHELL, None, &["/system/bin/getprop", READY])?;
    let before_pid = before.child.id();
    let (code, out, err) = finish(&mut before, Duration::from_secs(25));
    emit_guest("getprop-before", before_pid, code, &out, &err);
    if code != Some(0) || out.contains("true") || !opened(&err, "/dev/__properties__/property_info")
    {
        return blocker(
            "getprop before servicemanager did not show an absent ready",
            &format!("exit={code:?} stdout={out:?}"),
        );
    }

    let mut client = launch(
        linux_run,
        &root,
        SHELL,
        Some(binder_name),
        &["/system/bin/service", "check", "manager"],
    )?;
    let client_pid = client.child.id();
    if !wait_until_property_blocks(&mut client, Duration::from_secs(25))? {
        emit_guest(
            "service-check-manager-not-waiting",
            client_pid,
            None,
            &stdout_of(&client),
            &stderr_of(&client),
        );
        return blocker(
            "service check manager opened binder or exited before servicemanager published ready",
            "",
        );
    }
    emit_guest(
        "service-check-manager-waiting",
        client_pid,
        None,
        &stdout_of(&client),
        &stderr_of(&client),
    );
    if binder_device_opened(&stderr_of(&client)) || server.get(READY).is_some() {
        return blocker(
            "ready or /dev/binder was already visible while the client was supposed to be waiting",
            &server.log(),
        );
    }

    let mut sm = launch(
        linux_run,
        &root,
        SERVICEMANAGER_IDENTITY,
        Some(binder_name),
        &["/system/bin/servicemanager"],
    )?;
    let sm_pid = sm.child.id();
    let published = format!(
        "property-service set pid={sm_pid} uid=1000 context=u:r:servicemanager:s0 name={READY} value=true reply=0"
    );
    let set_seen = wait_until(Duration::from_secs(20), || {
        server.log().contains(&published) || sm.child.try_wait().ok().flatten().is_some()
    });
    emit_guest(
        "servicemanager-after-set",
        sm_pid,
        None,
        &stdout_of(&sm),
        &stderr_of(&sm),
    );
    if !set_seen || !server.log().contains(&published) || server.get(READY).as_deref() != Some("true")
    {
        return blocker(
            "servicemanager did not publish servicemanager.ready",
            &format!("want {published}\n{}", server.log()),
        );
    }
    println!("integrated: {published}");

    let (client_code, client_out, client_err) = finish(&mut client, Duration::from_secs(20));
    emit_guest(
        "service-check-manager",
        client_pid,
        client_code,
        &client_out,
        &client_err,
    );
    if client_code != Some(0)
        || !client_out.contains("Service manager: found")
        || !binder_device_opened(&client_err)
        || !saw_return(&client_err, "BR_REPLY")
    {
        return blocker(
            "the waiting service client did not find the manager after the publish",
            &format!("exit={client_code:?} stdout={client_out:?}"),
        );
    }

    let mut after = launch(linux_run, &root, SHELL, None, &["/system/bin/getprop", READY])?;
    let after_pid = after.child.id();
    let (after_code, after_out, after_err) = finish(&mut after, Duration::from_secs(25));
    emit_guest("getprop-after", after_pid, after_code, &after_out, &after_err);
    if after_code != Some(0) || after_out != "true\n" || after_pid == client_pid || after_pid == sm_pid
    {
        return blocker(
            "a later getprop did not read the value servicemanager published",
            &format!("pid={after_pid} exit={after_code:?} stdout={after_out:?}"),
        );
    }

    let mut missing = launch(
        linux_run,
        &root,
        SHELL,
        Some(binder_name),
        &["/system/bin/service", "check", PING],
    )?;
    let missing_pid = missing.child.id();
    let (missing_code, missing_out, missing_err) = finish(&mut missing, Duration::from_secs(20));
    emit_guest(
        "service-check-ping-before",
        missing_pid,
        missing_code,
        &missing_out,
        &missing_err,
    );
    if missing_code != Some(0)
        || !missing_out.contains(&format!("Service {PING}: not found"))
        || !binder_device_opened(&missing_err)
        || !saw_return(&missing_err, "BR_REPLY")
    {
        return blocker(
            "service check did not report the probe name missing before addService",
            &format!("stdout={missing_out:?}"),
        );
    }

    let mut serve = launch(
        linux_run,
        &root,
        SHELL,
        Some(binder_name),
        &["/system/bin/libbinder-ping", "serve", PING],
    )?;
    let serve_pid = serve.child.id();
    let serving = format!("serving {PING} pid={serve_pid}");
    let registered = wait_until(Duration::from_secs(20), || {
        stdout_of(&serve).contains(&serving) || serve.child.try_wait().ok().flatten().is_some()
    });
    emit_guest(
        "libbinder-ping-serve",
        serve_pid,
        None,
        &stdout_of(&serve),
        &stderr_of(&serve),
    );
    if !registered || !stdout_of(&serve).contains(&serving) || !binder_device_opened(&stderr_of(&serve))
    {
        return blocker("libbinder-ping serve did not register on this servicemanager", "");
    }

    let mut call = launch(
        linux_run,
        &root,
        SHELL,
        Some(binder_name),
        &["/system/bin/libbinder-ping", "call", PING],
    )?;
    let call_pid = call.child.id();
    let (call_code, call_out, call_err) = finish(&mut call, Duration::from_secs(20));
    emit_guest("libbinder-ping-call", call_pid, call_code, &call_out, &call_err);
    let Some((value, reply_server, reply_caller)) = parcel_reply(&call_out) else {
        return blocker("call did not print a parcel reply", &format!("stdout={call_out:?}"));
    };
    if call_code != Some(0)
        || value != 2
        || reply_server != serve_pid
        || reply_caller != call_pid
        || !binder_device_opened(&call_err)
        || !saw_return(&call_err, "BR_REPLY")
        || reply_caller == sm_pid
        || reply_caller == client_pid
    {
        return blocker(
            "parcel was not value=2 between the two guests on this servicemanager",
            &format!(
                "value={value} server_pid={reply_server} caller_pid={reply_caller} exit={call_code:?}"
            ),
        );
    }
    if serve.child.try_wait().ok().flatten().is_some() || sm.child.try_wait().ok().flatten().is_some()
    {
        return blocker("servicemanager or the probe server exited before the call returned", "");
    }
    drop(call);
    drop(serve);
    drop(sm);
    drop(server);
    if root.join("dev/socket/property_service").exists() {
        return blocker("property socket was left behind", "");
    }
    if property_area(&root).exists() {
        return blocker("property area was left behind", "the server must remove the area it created");
    }
    println!(
        "integrated ok client={client_pid} servicemanager={sm_pid} getprop={after_pid} serve={serve_pid} call={call_pid}"
    );
    println!("integrated: this is not ART and not a reDroid boot");
    println!("integrated: identity denial was not run as a guest");
    Ok(())
}

fn blocker(why: &str, detail: &str) -> Result<(), String> {
    Err(format!("integrated: first blocker: {why}\n{detail}"))
}

/// The client has mapped the property area and has not opened `/dev/binder`.
/// That is the wait. A ready value already in the area lets it open binder
/// immediately, which is not this matrix.
fn wait_until_property_blocks(guest: &mut property::Guest, limit: Duration) -> Result<bool, String> {
    let start = Instant::now();
    let mut saw_info: Option<Instant> = None;
    loop {
        if guest.child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(false);
        }
        let err = stderr_of(guest);
        if binder_device_opened(&err) {
            return Ok(false);
        }
        if opened(&err, "/dev/__properties__/property_info") {
            let since = *saw_info.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_millis(400) {
                return Ok(!binder_device_opened(&stderr_of(guest)));
            }
        }
        if start.elapsed() >= limit {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_until(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if ready() {
            return true;
        }
        if start.elapsed() >= limit {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
