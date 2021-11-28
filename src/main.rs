use std::path::PathBuf;

const HELP: &str = "dld 0.1.0

USAGE:
  dld [OPTIONS] INPUTS

FLAGS:
  -h, --help    Prints help information

OPTIONS:
  -o FILE       Where to output the ELF file.
  -L DIRECTORY  A directory in which to look for libraries.
                Can be specified multiple times.
  -l LIBRARY    A library to link against.
                Can be specified multiple times.
";

#[derive(Debug)]
struct AppArgs {
    output: Option<PathBuf>,
    inputs: Vec<PathBuf>,
    search_paths: Vec<PathBuf>,
    libs: Vec<PathBuf>,
    help: bool,
}

fn main() -> Result<(), String> {
    env_logger::init();
    let mut args = parse_args();
    if args.help {
        println!("{}", HELP);
        return Ok(());
    }
    search_for_libraries(&mut args)
        .map_err(|e| format!("Couldn't find library: {}", e.display()))?;
    let out = args.output.unwrap_or_else(|| PathBuf::from("out"));
    if let Err(e) = dld::link(&args.inputs, &out) {
        Err(format!("{}", e))
    } else {
        println!("Elf executable in: {}", out.display());
        Ok(())
    }
}

fn parse_args() -> AppArgs {
    let mut pargs = pico_args::Arguments::from_env();
    let output = pargs.opt_value_from_os_str("-o", parse_path).unwrap();
    let help = pargs.contains(["-h", "--help"]);
    let mut search_paths = pargs.values_from_os_str("-L", parse_path).unwrap();
    let mut libs = pargs.values_from_os_str("-l", parse_path).unwrap();
    let mut inputs = vec![];
    for arg in pargs.finish().iter().filter_map(|a| a.to_str()) {
        if let Some(arg) = arg.strip_prefix("-L") {
            search_paths.push(arg.into());
        } else if let Some(lib) = arg.strip_prefix("-l") {
            libs.push(lib.into());
        } else {
            inputs.push(arg.into());
        }
    }
    AppArgs { output, help, search_paths, libs, inputs }
}

fn parse_path(s: &std::ffi::OsStr) -> Result<PathBuf, &'static str> {
    Ok(s.into())
}

fn search_for_libraries(args: &mut AppArgs) -> Result<(), &PathBuf> {
    for lib in &args.libs {
        let mut found = false;
        for dir in &args.search_paths {
            let input = dir.join(format!("lib{}.a", lib.display()));
            if input.exists() {
                args.inputs.push(input);
                found = true;
                break;
            }
        }
        if !found {
            return Err(lib);
        }
    }
    Ok(())
}
