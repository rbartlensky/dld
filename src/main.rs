use std::path::PathBuf;

const HELP: &str = "dld 0.1.0

USAGE:
  dld [OPTIONS] INPUTS

FLAGS:
  -h, --help    Prints help information

OPTIONS:
  -o FILE       Where to output the ELF file.
";

#[derive(Debug)]
struct AppArgs {
    output: Option<PathBuf>,
    inputs: Vec<PathBuf>,
    help: bool,
}

fn main() -> Result<(), String> {
    let args = parse_args();
    if args.help {
        println!("{}", HELP);
        return Ok(());
    }
    let out = args.output.unwrap_or(PathBuf::from("out"));
    if let Err(e) = dld::link(&args.inputs, &out) {
        Err(format!("{}", e))
    } else {
        println!("Elf executable in: {}", out.display());
        Ok(())
    }
}

fn parse_args() -> AppArgs {
    let mut pargs = pico_args::Arguments::from_env();
    let args = AppArgs {
        output: pargs.opt_value_from_os_str("-o", parse_path).unwrap(),
        help: pargs.contains(["-h", "--help"]),
        inputs: pargs.finish().iter().map(PathBuf::from).collect(),
    };

    args
}

fn parse_path(s: &std::ffi::OsStr) -> Result<PathBuf, &'static str> {
    Ok(s.into())
}
