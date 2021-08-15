pub mod error;
mod elf;
mod name;
mod symbol;
mod serialize;

use error::{Error, ErrorExt, ErrorType};
use goblin::{
    elf::Elf,
    elf64::section_header::{SHT_NOBITS, SHT_PROGBITS},
};
use std::{
    fs::read,
    path::{Path, PathBuf},
};

pub fn link<'p>(inputs: &'p [PathBuf], output: &'p Path) -> Result<(), Error<'p>> {
    let mut writer = elf::Writer::new(output).map_path_err(output)?;
    for input in inputs.iter().map(|p| p.as_path()) {
        let buf = read(input).map_path_err(input)?;
        let obj = goblin::Object::parse(&buf).map_path_err(input)?;
        if let goblin::Object::Elf(elf) = obj {
            for section in elf
                .section_headers
                .iter()
                .filter(|sh| sh.sh_type == SHT_PROGBITS || sh.sh_type == SHT_NOBITS)
            {
                let name = get_section_name(&elf, section.sh_name).map_path_err(input)?;
                writer.push_section(name.into(), section, section.file_range().map(|r| &buf[r]));
            }
            for symbol in &elf.syms {
                let name = get_symbol_name(&elf, symbol.st_name).map_path_err(input)?;
                writer.add_symbol(symbol.into(), name, input).map_path_err(input)?;
            }
        } else {
            return Err(Error::new(input, ErrorType::NotAnElf));
        }
    }
    writer.write_to_disk();

    Ok(())
}

fn get_section_name<'e>(elf: &Elf<'e>, index: usize) -> Result<&'e str, String> {
    elf.shdr_strtab.get_at(index).ok_or_else(|| "Symbol not found in strtab.".to_string())
}

fn get_symbol_name<'e>(elf: &Elf<'e>, index: usize) -> Result<&'e str, String> {
    elf.strtab.get_at(index).ok_or_else(|| "Symbol not found in strtab.".to_string())
}
