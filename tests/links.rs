use std::{path::Path, process::Command};

fn link_with_clang(dld: &Path, file: &Path) {
    let mut cmd = Command::new("clang");
    cmd.args(&["-o", "./test"]).arg(file).arg(format!("-fuse-ld={}", dld.display()));
    dbg!(&cmd);
    let status_code = cmd.status().unwrap().code().unwrap();
    assert_eq!(status_code, 0);
}

#[test]
fn links() {
    let dld_path = Path::new("/home/robert/projects/dld/target/debug/dld");
    for entry in std::fs::read_dir("./tests/c/").unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            println!("Linking {:?}", entry);
            link_with_clang(dld_path, &entry.path());
            assert_eq!(Command::new("./test").status().unwrap().code().unwrap(), 0);
        }
    }
}
