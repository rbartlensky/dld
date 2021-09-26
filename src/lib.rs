pub mod error;
mod elf;
mod name;
mod symbol;
mod serialize;

use error::{Error, ErrorExt};
use goblin::{
    elf::{reloc::*, Elf},
    elf64::section_header::{SHN_ABS, SHN_COMMON, SHT_DYNAMIC, SHT_HASH, SHT_NOTE, SHT_PROGBITS},
};
use std::{
    collections::HashMap,
    fs::read,
    path::{Path, PathBuf},
};

pub fn link<'p>(inputs: &'p [PathBuf], output: &'p Path) -> Result<(), Error<'p>> {
    let mut writer = elf::Writer::new(output).map_path_err(output)?;
    let mut section_relocations = HashMap::new();
    for input in inputs.iter().map(|p| p.as_path()) {
        let buf = read(input).map_path_err(input)?;
        let elf = Elf::parse(&buf).map_path_err(input)?;
        for (i, section) in elf.section_headers.iter().enumerate().filter(|(_, sh)| {
            // TODO: not all sections are included
            [SHT_PROGBITS, SHT_HASH, SHT_DYNAMIC, SHT_NOTE].contains(&sh.sh_type)
        }) {
            let name = get_section_name(&elf, section.sh_name).map_path_err(input)?;
            let res =
                writer.push_section(name.into(), section, section.file_range().map(|r| &buf[r]));
            section_relocations.insert(i, res);
        }
        for symbol in &elf.syms {
            let name = get_symbol_name(&elf, symbol.st_name).map_path_err(input)?;
            let sec_ref =
                *section_relocations.get(&(symbol.st_shndx as usize)).unwrap_or(&elf::SectionRef {
                    index: symbol.st_shndx as usize,
                    insertion_point: 0,
                });
            writer.add_symbol(symbol.into(), sec_ref, name, input).map_path_err(input)?;
        }
        for (_, rels) in elf.shdr_relocs {
            for rel in rels.iter().filter(|r| r.r_sym != 0) {
                let symbol = &elf.syms.get(rel.r_sym as usize - 1).unwrap();
                if symbol.st_shndx == SHN_ABS as usize || symbol.st_shndx == SHN_COMMON as usize {
                    continue;
                }
                let s = symbol.st_value;
                // XXX: is 0 ok for REL?
                let a = rel.r_addend.unwrap_or_default();
                let p = rel.r_offset;
                let value = match rel.r_type {
                    R_X86_64_NONE => s,
                    R_X86_64_64 => s + a as u64,
                    R_X86_64_PC32 => s + (a - p as i64) as u64,
                    x => unimplemented!("Relocation {}", x),
                };
                writer.patch_section(
                    section_relocations[&(symbol.st_shndx as usize)].index,
                    rel.r_offset as usize,
                    value,
                );
            }
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
