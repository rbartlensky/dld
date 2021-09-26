use dld;
use tempfile::NamedTempFile;

use std::{path::PathBuf, process::Command};

#[test]
fn same_objdump_as_ld() {
    let to_link = [PathBuf::from("./tests/obj-files/f.o"), PathBuf::from("./tests/obj-files/f2.o")];
    let file = NamedTempFile::new().unwrap();

    dld::link(&to_link, file.path()).unwrap();
    let objdump_output = Command::new("objdump").arg("-d").arg(file.path()).output().unwrap();

    // This is assuming `ld` is GNU ld for now
    Command::new("ld").arg("-o").arg(file.path()).args(to_link).output().unwrap();
    let objdump_output_ld = Command::new("objdump").arg("-d").arg(file.path()).output().unwrap();

    assert_eq!(objdump_output.stdout, objdump_output_ld.stdout);
}
