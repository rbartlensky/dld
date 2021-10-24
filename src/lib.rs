pub mod error;
mod elf;
mod name;
mod symbol;
mod serialize;

use error::{Error, ErrorExt};
use goblin::{
    elf::{reloc::*, Elf},
    elf32::section_header::SHN_UNDEF,
    elf64::section_header::{
        SHN_ABS, SHN_COMMON, SHT_DYNAMIC, SHT_DYNSYM, SHT_REL, SHT_RELA, SHT_SHLIB, SHT_STRTAB,
        SHT_SYMTAB,
    },
};
use std::{
    collections::HashMap,
    fs::read,
    path::{Path, PathBuf},
};

const SKIPPED_SECTIONS: &[u32] =
    &[SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB, SHT_RELA, SHT_DYNAMIC, SHT_REL, SHT_SHLIB];

struct Input<'a> {
    elf: Elf<'a>,
    section_relocations: HashMap<usize, elf::SectionRef>,
}

#[allow(clippy::many_single_char_names)]
pub fn link<'p>(inputs: &'p [PathBuf], output: &'p Path) -> Result<(), Error<'p>> {
    let mut writer = elf::Writer::new(output).map_path_err(output)?;
    let inputs = inputs
        .iter()
        .map(|p| {
            let input = p.as_path();
            let elf = read(input).map_path_err(input)?;
            Ok((elf, input))
        })
        .collect::<Result<Vec<(Vec<u8>, &Path)>, Error<'p>>>()?;
    let mut elfs = Vec::with_capacity(inputs.len());
    for (buf, input) in &inputs {
        let elf = Elf::parse(buf).map_path_err(input)?;
        let mut section_relocations = HashMap::new();
        for (i, section) in elf
            .section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| !SKIPPED_SECTIONS.contains(&sh.sh_type))
        {
            let name = get_section_name(&elf, section.sh_name).map_path_err(input)?;
            // empty section? don't care then
            if let Some(res) =
                writer.push_section(name.into(), section, section.file_range().map(|r| &buf[r]))
            {
                section_relocations.insert(i, res);
            }
        }
        for symbol in &elf.syms {
            let name = get_symbol_name(&elf, symbol.st_name).map_path_err(input)?;
            // if the symbol is pointing to an empty section, then we don't care about it
            let sec_ref =
                if let Some(sec_ref) = section_relocations.get(&(symbol.st_shndx as usize)) {
                    *sec_ref
                } else if symbol.st_shndx == SHN_ABS as usize {
                    crate::elf::SectionRef { index: symbol.st_shndx, insertion_point: 0 }
                } else {
                    continue;
                };
            writer.add_symbol(symbol.into(), sec_ref, name, input).map_path_err(input)?;
        }
        // just scan relocs for now to find out how many GOT entries we have
        for (_, rels) in &elf.shdr_relocs {
            for rel in rels.iter().filter(|r| r.r_sym != 0) {
                let symbol = &elf.syms.get(rel.r_sym as usize - 1).unwrap();
                if symbol.st_shndx == SHN_UNDEF as usize || symbol.st_shndx == SHN_COMMON as usize {
                    continue;
                }
                if section_relocations.get(&(symbol.st_shndx as usize)).is_none() {
                    continue;
                }
                match rel.r_type {
                    R_X86_64_32 | R_X86_64_NONE | R_X86_64_64 | R_X86_64_PC32 | R_X86_64_SIZE64 => {
                    }
                    R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => {
                        let name = get_symbol_name(&elf, symbol.st_name).map_path_err(input)?;
                        writer.got_entry(name);
                    }
                    R_X86_64_PLT32 => {
                        unimplemented!("PLT relocations")
                    }
                    x => unimplemented!("Relocation {:?}", x),
                }
            }
        }
        elfs.push(Input { elf, section_relocations });
    }
    writer.compute_sections();
    for (elf, section_relocations) in elfs.iter().map(|e| (&e.elf, &e.section_relocations)) {
        for (_, rels) in &elf.shdr_relocs {
            // TODO: too much repetition
            for rel in rels.iter().filter(|r| r.r_sym != 0) {
                let symbol = &elf.syms.get(rel.r_sym as usize - 1).unwrap();
                if symbol.st_shndx == SHN_UNDEF as usize || symbol.st_shndx == SHN_COMMON as usize {
                    continue;
                }
                let index = if let Some(sec) = section_relocations.get(&(symbol.st_shndx as usize))
                {
                    sec.index
                } else {
                    continue;
                };
                let s = symbol.st_value;
                // XXX: is 0 ok for REL?
                let a = rel.r_addend.unwrap_or_default();
                let p = rel.r_offset;
                let z = symbol.st_size;
                let value = match rel.r_type {
                    R_X86_64_NONE => s,
                    R_X86_64_32 | R_X86_64_64 => s + a as u64,
                    R_X86_64_PC32 => s + (a - p as i64) as u64,
                    R_X86_64_SIZE64 => z + a as u64,
                    R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => {
                        let name = get_symbol_name(elf, symbol.st_name).unwrap();
                        let g = writer.got_entry(name);
                        let got = writer.got_address();
                        let _ = g as u64 + got + (a - p as i64) as u64;
                        unimplemented!("GOTPCRELX relocations");
                    }
                    x => unimplemented!("Relocation {:?}", x),
                };
                // TODO: check value for truncation
                writer.patch_section(index, rel.r_offset as usize, value as u32);
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
