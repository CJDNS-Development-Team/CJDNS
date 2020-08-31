//! CJDNS supernode

use std::error::Error;
use std::path::{Path, PathBuf};

use clap::Clap;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
    }
}

type Err = Box<dyn Error>;

async fn run() -> Result<(), Err> {
    let opts: Opts = Opts::parse();
    let _ = opts.config_file_path();

    todo!()
}

/// CJDNS supernode.
#[derive(Clap)]
#[clap(version = "0.1.0", author = "The CJDNS development team")]
struct Opts {
    /// Config file path (default `./config`)
    #[clap(long = "config")]
    config: Option<PathBuf>,
}

impl Opts {
    fn config_file_path(&self) -> &Path {
        self.config.as_ref().map(PathBuf::as_path).unwrap_or(Path::new("./config"))
    }
}