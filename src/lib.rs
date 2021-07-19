pub mod error;

use error::{Error, ErrorExt, ErrorType};
use goblin::{
    elf::{
        sym::{STB_GLOBAL, STB_WEAK, STT_NOTYPE},
        Elf,
    },
    Object,
};
use std::{
    collections::{hash_map::Entry, HashMap},
    fs::{read, write},
    path::{Path, PathBuf},
};

pub fn link<'p>(inputs: &'p [PathBuf], output: &'p Path) -> Result<(), Error<'p>> {
    let mut symbols = HashMap::new();
    for input in inputs.iter().map(|p| p.as_path()) {
        let buf = read(input).map_path_err(input)?;
        match Object::parse(&buf).map_path_err(input)? {
            Object::Elf(elf) => gather_symbols(elf, &mut symbols).map_path_err(input)?,
            _ => return Err(Error::new(input, ErrorType::NotAnElf)),
        }
    }
    write(output, format!("{:?}\n", symbols)).map_path_err(output)?;
    Ok(())
}

fn gather_symbols(elf: Elf, symbol_table: &mut HashMap<String, u8>) -> Result<(), ErrorType> {
    for sym in elf.syms.iter().filter(|sym| {
        let bind = sym.st_bind();
        (bind == STB_WEAK || bind == STB_GLOBAL) && sym.st_type() != STT_NOTYPE
    }) {
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .ok_or_else(|| "Symbol not found in strtab.".to_string())?;
        let is_weak = sym.st_bind() == STB_WEAK;
        match symbol_table.entry(name.into()) {
            Entry::Occupied(_) => {
                // Do nothing for a weak symbol that we have already found
                if !is_weak {
                    return Err(ErrorType::Other(format!("Symbol {} already defined.", name)));
                }
            }
            Entry::Vacant(v) => {
                v.insert(sym.st_type());
            }
        }
    }
    Ok(())
}
