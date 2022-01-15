use dld::elf::{BuildId, Emulation, HashStyle, Options};
use goblin::elf32::header::ET_DYN;
use std::{collections::HashSet, io::Read, path::PathBuf, str::FromStr};

mod linker_script;

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

#[derive(Debug, Default)]
struct AppArgs {
    opts: Options,
    objects: Vec<PathBuf>,
    archives: HashSet<PathBuf>,
    search_paths: HashSet<PathBuf>,
    scripts: Vec<PathBuf>,
    inputs: Vec<(PathBuf, bool)>,
    help: bool,
    as_needed: bool,
}

fn main() -> Result<(), String> {
    env_logger::init();
    let mut args = parse_args()?;
    if args.help {
        println!("{}", HELP);
        return Ok(());
    }
    while let Some(script) = args.scripts.pop() {
        let new_args = linker_script::parse(&std::fs::read_to_string(script).unwrap()).unwrap();
        if !new_args.is_empty() {
            handle_linker_args(&mut new_args.into_iter().peekable(), &mut args)?;
            let _ = search_for_inputs(&mut args);
        }
    }
    log::debug!("{:#?}", args);
    let linker = dld::Linker { options: args.opts, objects: args.objects, archives: args.archives };
    if let Err(e) = linker.link() {
        Err(format!("{}", e))
    } else {
        println!("Elf executable in: {}", linker.options.output.display());
        Ok(())
    }
}

#[derive(Debug)]
enum FileType {
    Archive,
    ElfObject,
    ElfSharedLib,
    Text,
}

fn file_type(input: &std::path::Path) -> std::io::Result<FileType> {
    let mut f = std::fs::File::open(&input)?;
    let mut header = [0; 18];
    if f.read_exact(&mut header).is_err() {
        return Ok(FileType::Text);
    }
    if header.starts_with(goblin::archive::MAGIC) {
        Ok(FileType::Archive)
    } else if header.starts_with(&[0x7f, b'E', b'L', b'F']) {
        if header.ends_with(&[ET_DYN as u8, ((ET_DYN & 0xff00) >> 8) as u8]) {
            Ok(FileType::ElfSharedLib)
        } else {
            Ok(FileType::ElfObject)
        }
    } else {
        Ok(FileType::Text)
    }
}

fn parse_args() -> Result<AppArgs, String> {
    let mut args = std::env::args().peekable();
    let _ = args.next();
    let mut app = Default::default();
    handle_linker_args(&mut args, &mut app)?;
    search_for_inputs(&mut app).map_err(|e| format!("Couldn't find library {}", e.display()))?;
    Ok(app)
}

fn handle_linker_args(
    args: &mut std::iter::Peekable<impl std::iter::Iterator<Item = String>>,
    app: &mut AppArgs,
) -> Result<(), String> {
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--build-id" => {
                if let Some(arg) = args.peek() {
                    if !arg.starts_with("--") && !arg.starts_with('-') {
                        app.opts.build_id = Some(BuildId::from_str(&args.next().unwrap())?);
                    } else {
                        app.opts.build_id = Some(BuildId::default());
                    }
                } else {
                    app.opts.build_id = Some(BuildId::default());
                }
                continue;
            }
            "-m" => {
                let em = args
                    .next()
                    .ok_or_else(|| "Missing argument <EMULATION> for '-m'.".to_string())?;
                app.opts.emulation = Emulation::from_str(&em)?;
                continue;
            }
            "-o" => {
                let out =
                    args.next().ok_or_else(|| "Missing argument <OUTPUT> for '-o'.".to_string())?;
                app.opts.output = out.into();
                continue;
            }
            "--eh-frame-hdr" => {
                app.opts.eh_frame_hdr = true;
                continue;
            }
            "--help" | "-h" => {
                app.help = true;
                continue;
            }
            "-dynamic-linker" => {
                let linker = args
                    .next()
                    .ok_or_else(|| "Missing argument <PATH> for '-dynamic-linker'.".to_string())?;
                app.opts.dynamic_linker = linker.into();
                continue;
            }
            "-L" => {
                let path =
                    args.next().ok_or_else(|| "Missing argument <PATH> for '-L'.".to_string())?;
                app.search_paths.insert(path.into());
                continue;
            }
            "-l" => {
                let path =
                    args.next().ok_or_else(|| "Missing argument <PATH> for '-l'.".to_string())?;
                app.inputs.push((path.into(), app.as_needed));
                continue;
            }
            "--as-needed" => {
                app.as_needed = true;
                continue;
            }
            "--no-as-needed" => {
                app.as_needed = false;
                continue;
            }
            "--start-group" | "--end-group" => {
                continue;
            }
            _ => {
                // a "special" arg incoming...
            }
        }
        if let Some(arg) = arg.strip_prefix("-L") {
            app.search_paths.insert(PathBuf::from(arg).canonicalize().unwrap());
        } else if let Some(lib) = arg.strip_prefix("-l") {
            app.inputs.push((lib.into(), app.as_needed));
        } else if let Some(arg) = arg.strip_prefix("--hash-style=") {
            app.opts.hash_style = HashStyle::from_str(arg)?;
        } else {
            app.inputs.push((arg.into(), app.as_needed));
        }
    }
    Ok(())
}

fn search_for_inputs(args: &mut AppArgs) -> Result<(), PathBuf> {
    for (lib, as_needed) in args.inputs.drain(..) {
        let mut found = None;
        if lib.exists() && lib.is_file() {
            found = Some(lib.clone());
        }
        for kind in ["so", "a"] {
            if found.is_some() {
                break;
            }
            for dir in &args.search_paths {
                let p = dir.join(&lib);
                if p.exists() && p.is_file() {
                    found = Some(p);
                    break;
                }
                let input = dir.join(format!("lib{}.{}", lib.display(), kind));
                if input.exists() && input.is_file() {
                    found = Some(input);
                }
            }
        }
        if let Some(lib) = found.take() {
            let file_type = file_type(&lib).unwrap();
            match file_type {
                FileType::ElfObject => {
                    args.objects.push(lib.canonicalize().unwrap());
                }
                FileType::Archive => {
                    args.archives.insert(lib.canonicalize().unwrap());
                }
                FileType::ElfSharedLib => args.opts.shared_libs.push((lib, as_needed)),
                FileType::Text => args.scripts.push(lib),
            }
        } else {
            return Err(lib);
        }
    }
    Ok(())
}
