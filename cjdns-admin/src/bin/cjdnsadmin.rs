//! CJDNS Admin tool

use std::{env, path};

use anyhow::Error;
use regex::Regex;

use cjdns_admin::{msgs::GenericResponsePayload, ArgValue, ArgValues, Func};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
    }
}

async fn run() -> Result<(), Error> {
    let mut cjdns = cjdns_admin::connect(None).await?;

    let args = env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        let bin_path: path::PathBuf = env::args_os().next().expect("missing binary name (bad OS?)").into();
        let bin_name = bin_path.file_name().expect("missing file name").to_string_lossy();
        eprintln!("Usage: {} 'ping()' ## For example to send a ping request", bin_name);
        eprintln!("List of available RPC requests with parameters is as follows:");
        eprintln!("{}", cjdns.functions)
    } else {
        let fn_call_str = args.last().cloned().ok_or_else(|| Error::msg("empty program args"))?;

        let (fn_name, fn_args) = split_fn_invocation_str(&fn_call_str).map_err(|_| Error::msg("bad function invocation expression"))?;

        let fn_args = parse_remote_fn_args(&fn_args).map_err(|_| Error::msg("bad function arguments"))?;

        let func = cjdns.functions.find(&fn_name).ok_or_else(|| Error::msg("unknown function name"))?;
        let fn_args = make_args(func, fn_args);

        let res = cjdns.invoke::<_, GenericResponsePayload>(&fn_name, fn_args).await?;
        println!("{:?}", res);
    };

    // Client disconnects automatically when `cjdns` drops out of scope

    Ok(())
}

fn split_fn_invocation_str(s: &str) -> Result<(String, String), ()> {
    // Regexp for function invocation, e.g. `foo_func(42, "ololo")`, captures func name and arg list.
    let re_fn_call = Regex::new(r"([\w]+)\(([^)]*)\)").expect("bad regex");

    let caps = re_fn_call.captures(s).ok_or(())?;
    let name = caps.get(1).ok_or(())?.as_str().to_string();
    let args = caps.get(2).ok_or(())?.as_str().to_string();

    Ok((name, args))
}

#[test]
fn test_split_fn_invocation_str() -> Result<(), ()> {
    let a = |func: &str, args: &str| (func.to_string(), args.to_string());
    assert_eq!(split_fn_invocation_str(r#"foo()"#)?, a("foo", r#""#));
    assert_eq!(split_fn_invocation_str(r#"bar(42)"#)?, a("bar", r#"42"#));
    assert_eq!(split_fn_invocation_str(r#"bar("baz")"#)?, a("bar", r#""baz""#));
    assert_eq!(split_fn_invocation_str(r#"baz(42, 43)"#)?, a("baz", r#"42, 43"#));
    assert_eq!(split_fn_invocation_str(r#"test(42,"arg",-42)"#)?, a("test", r#"42,"arg",-42"#));
    assert_eq!(split_fn_invocation_str(r#"test("str",42,"other")"#)?, a("test", r#""str",42,"other""#));
    assert_eq!(split_fn_invocation_str(r#"func(nonsense)"#)?, a("func", r#"nonsense"#)); // Makes no sense, but parses ok

    Ok(())
}

fn parse_remote_fn_args(s: &str) -> Result<Vec<Option<ArgValue>>, ()> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut fn_args = Vec::new();
    for arg in s.split(",").map(str::trim) {
        let arg = match arg.chars().next() {
            Some('-' | '0'..='9') => {
                let value = arg.parse().map_err(|_| ())?;
                ArgValue::Int(value).into()
            }
            Some('"') => {
                let n = arg.len();
                if n < 2 || arg.chars().last().ok_or(())? != '"' {
                    return Err(()); // Bad string argument - unpaired quotes
                }
                ArgValue::String(arg[1..n - 1].to_string()).into()
            }
            None => None,
            _ => return Err(()), // Bad argument - unknown type
        };
        fn_args.push(arg);
    }
    Ok(fn_args)
}

#[test]
fn test_parse_remote_fn_args() -> Result<(), ()> {
    assert_eq!(parse_remote_fn_args(r#""#)?, Vec::new());
    assert_eq!(parse_remote_fn_args(r#" "#)?, Vec::new());
    assert_eq!(parse_remote_fn_args(r#"42"#)?, vec![Some(ArgValue::Int(42))]);
    assert_eq!(parse_remote_fn_args(r#" 42 "#)?, vec![Some(ArgValue::Int(42))]);
    assert_eq!(parse_remote_fn_args(r#" 42"#)?, vec![Some(ArgValue::Int(42))]);
    assert_eq!(parse_remote_fn_args(r#"42 "#)?, vec![Some(ArgValue::Int(42))]);
    assert_eq!(parse_remote_fn_args(r#""foo""#)?, vec![Some(ArgValue::String("foo".to_string()))]);
    assert_eq!(
        parse_remote_fn_args(r#"42,"foo",-42"#)?,
        vec![Some(ArgValue::Int(42)), Some(ArgValue::String("foo".to_string())), Some(ArgValue::Int(-42))]
    );
    assert_eq!(
        parse_remote_fn_args(r#"42, "foo", -42"#)?,
        vec![Some(ArgValue::Int(42)), Some(ArgValue::String("foo".to_string())), Some(ArgValue::Int(-42))]
    );

    Ok(())
}

fn make_args(func: &Func, arg_values: Vec<Option<ArgValue>>) -> ArgValues {
    let mut args = ArgValues::new();
    for (arg, arg_value) in func.args.iter().zip(arg_values) {
        // Here we won't check argument types, required or not etc.
        // Let the remote side do all necessry checks and return error if needed.
        eprintln!("{}={:?}", arg.name, arg_value);
        if let Some(value) = arg_value {
            args.add(arg.name.clone(), value);
        }
    }
    args
}
