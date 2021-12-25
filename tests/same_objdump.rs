use dld;
use tempfile::NamedTempFile;

use std::{collections::HashSet, path::PathBuf, process::Command};

#[test]
fn same_objdump_as_ld() {
    let to_link = HashSet::from([PathBuf::from("./tests/obj-files/f.o"), PathBuf::from("./tests/obj-files/f2.o")]);
    let file = NamedTempFile::new().unwrap();

    let options = dld::elf::Options { output: file.path().to_owned(), ..Default::default() };
    let linker = dld::Linker {
        options,
        archives: Default::default(),
        objects: to_link.clone(),
    };
    linker.link().unwrap();
    let objdump_output = Command::new("objdump").arg("-d").arg(file.path()).output().unwrap();

    // This is assuming `ld` is GNU ld for now
    Command::new("ld").arg("-o").arg(file.path()).args(to_link).output().unwrap();
    let objdump_output_ld = Command::new("objdump").arg("-d").arg(file.path()).output().unwrap();

    assert_eq!(objdump_output.stdout, objdump_output_ld.stdout);
}
