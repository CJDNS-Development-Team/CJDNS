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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::msgs::RemoteFnArgDescr;

    use super::*;

    #[test]
    fn test_funcs() {
        let funcs = {
            let fns1 = mk_funcs(vec![
                ("fn_a", mk_args(vec![])),
                ("fn_c", mk_args(vec![("arg1", true, "Int"), ("arg2", true, "String")])),
            ]);
            let fns2 = mk_funcs(vec![
                ("fn_b", mk_args(vec![("c", false, "Int"), ("b", true, "Int"), ("a", false, "Int")])),
            ]);

            let mut funcs = Funcs::new();
            funcs.add_funcs(fns1);
            funcs.add_funcs(fns2);

            funcs
        };

        let a = |nm: &str, req: bool, typ: ArgType| {
            Arg {
                name: nm.to_string(),
                required: req,
                typ,
            }
        };

        assert_eq!(
            funcs,
            Funcs(vec![
                Func { name: "fn_a".to_string(), args: Args(vec![]) },
                Func { name: "fn_b".to_string(), args: Args(vec![a("b", true, ArgType::Int), a("a", false, ArgType::Int), a("c", false, ArgType::Int)]) },
                Func { name: "fn_c".to_string(), args: Args(vec![a("arg1", true, ArgType::Int), a("arg2", true, ArgType::String)]) },
            ])
        );
    }

    fn mk_funcs(list: Vec<(&str, RemoteFnArgsDescr)>) -> RemoteFnDescrs {
        let mut res = BTreeMap::new();
        for (name, args) in list {
            res.insert(name.to_string(), args);
        }
        res
    }

    fn mk_args(list: Vec<(&str, bool, &str)>) -> RemoteFnArgsDescr {
        let mut res = BTreeMap::new();
        for (name, req, typ) in list {
            let descr = RemoteFnArgDescr { required: if req { 1 } else { 0 }, typ: typ.to_string() };
            res.insert(name.to_string(), descr);
        }
        res
    }
}