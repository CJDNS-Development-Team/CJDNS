//! List of remote functions.

use std::fmt;

use crate::msgs::{RemoteFnArgsDescr, RemoteFnDescrs};

/// List of available remote functions.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Funcs(Vec<Func>);

/// Remote function description.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Func {
    /// Function name.
    pub name: String,
    /// Function argument descriptions.
    pub args: Args,
}

/// Remote function arguments description.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Args(Vec<Arg>);

/// Remote function argument description.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Arg {
    /// Argument name.
    pub name: String,
    /// Required argument flag.
    pub required: bool,
    /// Argument type.
    pub typ: ArgType,
}

/// Remote function argument type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ArgType {
    /// Integer argument.
    Int,
    /// String argument.
    String,
    /// Some other type which is not supported directly.
    Other(String),
}

impl Funcs {
    #[inline]
    pub(super) fn new() -> Self {
        Funcs(Vec::new())
    }

    pub(super) fn add_funcs(&mut self, fns: RemoteFnDescrs) {
        let Funcs(list) = self;
        for (fn_name, fn_descr) in fns.into_iter() {
            let func = Self::parse_fn(fn_name, fn_descr);
            list.push(func);
        }
        list.sort_by(|a, b| String::cmp(&a.name, &b.name));
    }

    fn parse_fn(fn_name: String, fn_args: RemoteFnArgsDescr) -> Func {
        let mut args = Vec::with_capacity(fn_args.len());
        for (arg_name, arg_descr) in fn_args {
            let arg = Arg {
                name: arg_name,
                required: arg_descr.required != 0,
                typ: arg_descr.typ.into(),
            };
            args.push(arg);
        }
        args.sort_by(|a, b| bool::cmp(&a.required, &b.required).reverse().then(String::cmp(&a.name, &b.name)));

        Func {
            name: fn_name,
            args: Args(args),
        }
    }

    /// Iterator over functions in this list returned in alphabetical order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item=&Func> {
        let Funcs(list) = self;
        list.iter()
    }

    /// Find function by name.
    #[inline]
    pub fn find(&self, name: &str) -> Option<&Func> {
        let Funcs(list) = self;
        list.iter().find(|&f| f.name == name)
    }
}

impl Args {
    /// Iterator over arguments in this list.
    /// Returns required args first in alphabetical order, then non-required in alphabetical order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item=&Arg> {
        let Args(list) = self;
        list.iter()
    }
}

impl From<String> for ArgType {
    #[inline]
    fn from(s: String) -> Self {
        match s.as_str() {
            "Int" => Self::Int,
            "String" => Self::String,
            _ => Self::Other(s),
        }
    }
}

impl fmt::Display for Funcs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Funcs(list) = self;
        for func in list {
            writeln!(f, "{}", func)?;
        }
        Ok(())
    }
}

impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({})", self.name, self.args)
    }
}

impl fmt::Display for Args {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Args(list) = self;
        let args: Vec<String> = list.iter().map(Arg::to_string).collect();
        write!(f, "{}", args.join(", "))
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.required {
            write!(f, "required ")?;
        }
        write!(f, "{} {}", self.typ, self.name)
    }
}

impl fmt::Display for ArgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ArgType::Int => write!(f, "Int"),
            ArgType::String => write!(f, "String"),
            ArgType::Other(t) => write!(f, "{}", t),
        }
    }
}
