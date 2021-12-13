use dld::elf::{BuildId, Emulation, HashStyle, Options};
use std::{path::PathBuf, str::FromStr};

const HELP: &str = "dld 0.1.0

USAGE:
  dld [OPTIONS] INPUTS

FLAGS:
  -h, --help    Prints help information

OPTIONS:
  -o FILE  Where to output the ELF file.
  -L DIRECTORY  A directory in which to look for libraries.
                Can be specified multiple times.
  -l LIBRARY  A library to link against.
              Can be specified multiple times.
  --build-id [STYLE]  Generate a unique identifier for the build.
  -m EMULATION  The emulation to use.
  --eh-frame-hdr  Create .eh_frame_hdr section.
  -dynamic-linker PATH  Set path to dynamic linker.
  --as-needed  Only set DT_NEEDED for following dynamic libs if used.
  --no-as-needed  Always set DT_NEEDED for following dynamic libs.
  --hash-style STYLE  Set hash style.
";

#[derive(Debug)]
struct AppArgs {
    opts: Options,
    inputs: Vec<PathBuf>,
    search_paths: Vec<PathBuf>,
    libs: Vec<(PathBuf, bool)>,
    help: bool,
}

fn main() -> Result<(), String> {
    env_logger::init();
    let mut args = parse_args()?;
    if args.help {
        println!("{}", HELP);
        return Ok(());
    }
    println!("{:#?}", args);
    search_for_libraries(&mut args)
        .map_err(|e| format!("Couldn't find library: {}", e.display()))?;

    if let Err(e) = dld::link(&args.inputs, &args.opts) {
        Err(format!("{}", e))
    } else {
        println!("Elf executable in: {}", args.opts.output.display());
        Ok(())
    }
}

fn parse_args() -> Result<AppArgs, String> {
    let mut args = std::env::args().peekable();
    let _ = args.next();
    let mut build_id = None;
    let mut hash_style = HashStyle::default();
    let mut emulation = Emulation::default();
    let mut output = PathBuf::from("./out");
    let mut eh_frame_hdr = false;
    let mut help = false;
    let mut dynamic_linker = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    let mut search_paths = vec![];
    let mut libs = vec![];
    let mut as_needed = false;
    let mut inputs = vec![];
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--build-id" => {
                if let Some(arg) = args.peek() {
                    if !arg.starts_with("--") && !arg.starts_with('-') {
                        build_id = Some(BuildId::from_str(&args.next().unwrap())?);
                    } else {
                        build_id = Some(BuildId::default());
                    }
                } else {
                    build_id = Some(BuildId::default());
                }
                continue;
            }
            "-m" => {
                let em = args
                    .next()
                    .ok_or_else(|| "Missing argument <EMULATION> for '-m'.".to_string())?;
                emulation = Emulation::from_str(&em)?;
                continue;
            }
            "-o" => {
                let out =
                    args.next().ok_or_else(|| "Missing argument <OUTPUT> for '-o'.".to_string())?;
                output = out.into();
                continue;
            }
            "--eh-frame-hdr" => {
                eh_frame_hdr = true;
                continue;
            }
            "--help" | "-h" => {
                help = true;
                continue;
            }
            "-dynamic-linker" => {
                let linker = args
                    .next()
                    .ok_or_else(|| "Missing argument <PATH> for '-dynamic-linker'.".to_string())?;
                dynamic_linker = linker.into();
                continue;
            }
            "-L" => {
                let path =
                    args.next().ok_or_else(|| "Missing argument <PATH> for '-L'.".to_string())?;
                search_paths.push(path.into());
                continue;
            }
            "-l" => {
                let path =
                    args.next().ok_or_else(|| "Missing argument <PATH> for '-l'.".to_string())?;
                libs.push((path.into(), as_needed));
                continue;
            }
            "--as-needed" => {
                as_needed = true;
                continue;
            }
            "--no-as-needed" => {
                as_needed = false;
                continue;
            }
            _ => {
                // a "special" arg incoming...
            }
        }
        if let Some(arg) = arg.strip_prefix("-L") {
            search_paths.push(arg.into());
        } else if let Some(lib) = arg.strip_prefix("-l") {
            libs.push((lib.into(), as_needed));
        } else if let Some(arg) = arg.strip_prefix("--hash-style=") {
            hash_style = HashStyle::from_str(arg)?;
        } else {
            inputs.push(arg.into());
        }
    }
    let opts = Options { build_id, eh_frame_hdr, emulation, hash_style, dynamic_linker, output };
    Ok(AppArgs { opts, help, search_paths, libs, inputs })
}

fn search_for_libraries(args: &mut AppArgs) -> Result<(), &PathBuf> {
    for (lib, _) in &args.libs {
        let mut found = false;
        for dir in &args.search_paths {
            for kind in ["a", "so"] {
                let input = dir.join(format!("lib{}.{}", lib.display(), kind));
                if input.exists() {
                    args.inputs.push(input);
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(lib);
        }
    }
    Ok(())
}
