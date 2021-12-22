use dld::elf::{BuildId, Emulation, HashStyle, Options};
use std::{io::Read, path::PathBuf, str::FromStr};

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
    search_paths: Vec<PathBuf>,
    scripts: Vec<PathBuf>,
    libs: Vec<(PathBuf, bool)>,
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
        println!("script! {}", script.display());
        let new_args =
            linker_script::parse(&std::fs::read_to_string(script).unwrap()).unwrap();
        if !new_args.is_empty() {
            handle_linker_args(&mut new_args.into_iter().peekable(), &mut args)?;
            let _ = search_for_libraries(&mut args);
        }
    }
    println!("{:#?}", args);
    if let Err(e) = dld::link(&args.objects, &args.opts) {
        Err(format!("{}", e))
    } else {
        println!("Elf executable in: {}", args.opts.output.display());
        Ok(())
    }
}

#[derive(Debug)]
enum FileType {
    Archive,
    Elf,
    Text,
}

fn file_type(input: &std::path::Path) -> std::io::Result<FileType> {
    let mut f = std::fs::File::open(&input)?;
    let mut header = [0; 16];
    f.read_exact(&mut header)?;
    println!("{:?} : hdr: {:x?}", input, header);
    if header.starts_with(goblin::archive::MAGIC) {
        Ok(FileType::Archive)
    } else if header.starts_with(&[0x7f, b'E', b'L', b'F']) {
        Ok(FileType::Elf)
    } else {
        Ok(FileType::Text)
    }
}

fn parse_args() -> Result<AppArgs, String> {
    let mut args = std::env::args().peekable();
    let _ = args.next();
    let mut app = Default::default();
    handle_linker_args(&mut args, &mut app)?;
    search_for_libraries(&mut app).map_err(|e| format!("Couldn't find library {}", e.display()))?;
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
                app.search_paths.push(path.into());
                continue;
            }
            "-l" => {
                let path =
                    args.next().ok_or_else(|| "Missing argument <PATH> for '-l'.".to_string())?;
                app.libs.push((path.into(), app.as_needed));
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
            _ => {
                // a "special" arg incoming...
            }
        }
        if let Some(arg) = arg.strip_prefix("-L") {
            app.search_paths.push(arg.into());
        } else if let Some(lib) = arg.strip_prefix("-l") {
            app.libs.push((lib.into(), app.as_needed));
        } else if let Some(arg) = arg.strip_prefix("--hash-style=") {
            app.opts.hash_style = HashStyle::from_str(arg)?;
        } else {
            app.libs.push((arg.into(), app.as_needed));
        }
    }
    Ok(())
}

fn search_for_libraries(args: &mut AppArgs) -> Result<(), PathBuf> {
    for (lib, _) in args.libs.drain(..) {
        log::trace!("{}", lib.display());
        let mut found = None;
        if lib.has_root() && lib.exists() && lib.is_file() {
            found = Some(lib.clone());
        }
        for dir in &args.search_paths {
            let p = dir.join(&lib);
            if p.exists() && p.is_file() {
                found = Some(p);
                break;
            }
            for kind in ["so", "a"] {
                let input = dir.join(format!("lib{}.{}", lib.display(), kind));
                if input.exists() && input.is_file() {
                    found = Some(input);
                }
            }
        }
        if let Some(lib) = found.take() {
            let file_type = file_type(&lib).unwrap();
            match file_type {
                FileType::Archive | FileType::Elf => args.objects.push(lib),
                FileType::Text => args.scripts.push(lib),
            }
        } else {
            return Err(lib);
        }
    }
    Ok(())
}
