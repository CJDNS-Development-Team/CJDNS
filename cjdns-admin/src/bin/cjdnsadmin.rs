//! CJDNS Admin tool

use std::{env, path};

use cjdns_admin::*;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
    }
}

fn run() -> Result<(), Error> {
    let cjdns = cjdns_admin::connect(None)?;

    let args = env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        let bin_path: path::PathBuf = env::args_os().next().expect("missing binary name (bad OS?)").into();
        let bin_name = bin_path.file_name().expect("missing file name").to_string_lossy();
        eprintln!("Usage: {} 'ping()' ## For example to send a ping request", bin_name);
        eprintln!("List of available RPC requests with parameters is as follows:");
        eprintln!("{}", cjdns.functions)
    } else {
        // TODO Properly parse function call string (like `foo(123, "bar", false, "baz")`) and prepare remote call name & args.
        //      For now can only execute function without arguments
        let fn_call = args.last().expect("empty program args");
        let fn_name = &fn_call[..fn_call.find("()").expect("empty func arg list expected")];
        let _ = cjdns.call_func(fn_name, (), false)?;
        // TODO Dump function call result as JSON
    };

    // Client disconnects automatically when `cjdns` drops out of scope

    Ok(())
}