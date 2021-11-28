pub mod error;
mod elf;
mod name;
mod symbol;
mod serialize;

use byteorder::{LittleEndian, WriteBytesExt};
use error::{Error, ErrorExt};
use goblin::{
    elf::{reloc::*, sym::Sym, Elf},
    elf64::{
        header::EM_X86_64,
        section_header::{
            SHT_DYNAMIC, SHT_DYNSYM, SHT_REL, SHT_RELA, SHT_SHLIB, SHT_STRTAB, SHT_SYMTAB,
        },
    },
};
use std::{
    collections::HashMap,
    convert::TryInto,
    fs::read,
    hash::{Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
};

const SKIPPED_SECTIONS: &[u32] =
    &[SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB, SHT_RELA, SHT_DYNAMIC, SHT_REL, SHT_SHLIB];

struct Input<'a> {
    elf: Elf<'a>,
    section_relocations: HashMap<usize, elf::SectionRef>,
    symbols: HashMap<Symbol, crate::elf::SymbolRef>,
}

struct Symbol(Sym);

impl PartialEq for Symbol {
    fn eq(&self, s2: &Self) -> bool {
        self.0.st_name == s2.0.st_name
            && self.0.st_info == s2.0.st_info
            && self.0.st_other == s2.0.st_other
            && self.0.st_shndx == s2.0.st_shndx
            && self.0.st_size == s2.0.st_size
    }
}

impl Eq for Symbol {}

impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.st_name.hash(state);
        self.0.st_info.hash(state);
        self.0.st_other.hash(state);
        self.0.st_shndx.hash(state);
        self.0.st_size.hash(state);
    }
}

pub fn link<'p>(inputs: &'p [PathBuf], output: &'p Path) -> Result<(), Error<'p>> {
    let mut writer = elf::Writer::new(output).map_path_err(output)?;
    let inputs2 = inputs;
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
        let mut symbols = HashMap::new();
        for (i, section) in elf
            .section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| !SKIPPED_SECTIONS.contains(&sh.sh_type))
        {
            let name = get_section_name(&elf, section.sh_name).map_path_err(input)?;
            let section_ref = writer.push_section(
                name.to_owned(),
                section,
                section.file_range().map(|r| &buf[r]),
            );
            log::trace!("Section '{}:{}' of {:?} mapped to {:?}", i, name, input, section_ref);
            section_relocations.insert(i, section_ref);
        }
        for symbol in &elf.syms {
            let name = get_symbol_name(&elf, symbol.st_name).map_path_err(input)?;
            let sec_ref = section_relocations.get(&(symbol.st_shndx as usize));
            let symbol_ref = writer
                .add_symbol(symbol.into(), sec_ref.cloned(), name, input)
                .map_path_err(input)?;
            if let Some(sym) = symbol_ref {
                symbols.insert(Symbol(symbol), sym);
            }
        }
        // just scan relocs for now to find out how many GOT entries we have
        for (_, rels) in &elf.shdr_relocs {
            for rel in rels.iter().filter(|r| r.r_sym != 0) {
                let symbol = &elf.syms.get(rel.r_sym as usize).unwrap();
                match rel.r_type {
                    R_X86_64_8 | R_X86_64_16 | R_X86_64_PC16 | R_X86_64_PC8 => {
                        return Err(Error::new(
                            input,
                            format!("Relocation {} not conforming to ABI.", rel.r_type),
                        ));
                    }
                    R_X86_64_32 | R_X86_64_32S | R_X86_64_NONE | R_X86_64_64 | R_X86_64_PC32
                    | R_X86_64_SIZE64 => {}
                    R_X86_64_GOT32
                    | R_X86_64_GOTPCREL
                    | R_X86_64_GOTOFF64
                    | R_X86_64_GOTPC32
                    | R_X86_64_GOTPCRELX
                    | R_X86_64_REX_GOTPCRELX => writer.add_got_entry(symbols[&Symbol(*symbol)]),
                    R_X86_64_PLT32 => writer.add_plt_entry(symbols[&Symbol(*symbol)]),
                    x => unimplemented!("Relocation {}", r_to_str(x, EM_X86_64)),
                }
            }
        }
        elfs.push(Input { elf, section_relocations, symbols });
    }
    writer.compute_sections().map_path_err(output)?;
    for (i, elf, section_relocations, symbols) in
        elfs.iter().enumerate().map(|(i, e)| (i, &e.elf, &e.section_relocations, &e.symbols))
    {
        log::debug!("Input: {}", inputs2[i].display());
        for (section_index, rels) in &elf.shdr_relocs {
            // TODO: too much repetition
            for rel in rels.iter() {
                let symbol = &elf.syms.get(rel.r_sym as usize).unwrap();
                let index = if let Some(sec) = section_relocations.get(&(section_index - 1)) {
                    *sec
                } else {
                    continue;
                };
                let symbol = if let Some(sym) = symbols.get(&Symbol(*symbol)) {
                    sym
                } else {
                    log::trace!(
                        "discarded relocation due to missing symbol {:?} type: {}",
                        rel,
                        r_to_str(rel.r_type, EM_X86_64)
                    );
                    continue;
                };
                log::trace!(
                    "applying relocation {:?} type: {}",
                    rel,
                    r_to_str(rel.r_type, EM_X86_64)
                );
                apply_relocation(elf, &mut writer, *symbol, &rel, index);
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

#[allow(clippy::many_single_char_names)]
fn apply_relocation(
    _elf: &Elf<'_>,
    writer: &mut crate::elf::Writer,
    symbol: crate::elf::SymbolRef,
    rel: &Reloc,
    section_index: crate::elf::SectionRef,
) {
    let symbol = writer.symbol(symbol);
    let is_symbol_local = !symbol.is_local();
    let s: i64 = symbol.st_value.try_into().unwrap();
    let a = rel.r_addend.unwrap_or_default();
    let p: i64 = rel.r_offset.try_into().unwrap();
    let _z = symbol.st_size;
    let got: i64 = writer.got_address().try_into().unwrap();
    match rel.r_type {
        R_X86_64_NONE => {}
        R_X86_64_64 => {
            let mut section_offset = writer.section_offset(section_index, rel.r_offset as usize);
            section_offset.write_i64::<LittleEndian>(s + a).unwrap()
        }
        R_X86_64_32 => {
            let mut section_offset = writer.section_offset(section_index, rel.r_offset as usize);
            section_offset.write_i32::<LittleEndian>((s + a).try_into().unwrap()).unwrap()
        }
        R_X86_64_PC32 => {
            let mut section_offset = writer.section_offset(section_index, rel.r_offset as usize);
            section_offset.write_i32::<LittleEndian>((s + a - p).try_into().unwrap()).unwrap()
        }
        R_X86_64_GOT32 => {
            let g: i64 = symbol.got_offset().unwrap().try_into().unwrap();
            let mut section_offset = writer.section_offset(section_index, rel.r_offset as usize);
            section_offset.write_i32::<LittleEndian>((g + a).try_into().unwrap()).unwrap()
        }
        R_X86_64_GOTPCRELX if is_symbol_local => {
            // -2 because the offset points to where we need to patch, but we want to
            // match the other two bytes to tell which instruction we're patching
            let buf = writer.section_offset(section_index, rel.r_offset as usize - 2);
            let value: i32 = (s + a - p).try_into().unwrap();
            match buf[..2] {
                // call *foo@GOTPCREL(%rip) -> call foo nop
                [0xff, 0x15] => {
                    buf[0] = 0xe8;
                    buf[1..5].as_mut().write_i32::<LittleEndian>(value).unwrap();
                    buf[5] = 0x90;
                }
                // jmp *foo@GOTPCREL(%rip) -> jmp foo nop
                [0xff, 0x25] => {
                    buf[0] = 0xe9;
                    buf[1..5].as_mut().write_i32::<LittleEndian>(value).unwrap();
                    buf[5] = 0x90;
                }
                ref x => unreachable!("{:?}", x),
            }
        }
        R_X86_64_REX_GOTPCRELX => {
            if is_symbol_local {
                let buf = writer.section_offset(section_index, rel.r_offset as usize - 3);
                let instr = match buf[..3] {
                    [0x48, 0x8b, 0x05] => [0x48, 0xc7, 0xc0], // mov 0x0(%rip),%rax -> mov $0x0,%rax
                    [0x48, 0x8b, 0x1d] => [0x48, 0xc7, 0xc3], // mov 0x0(%rip),%rbx -> mov $0x0,%rbx
                    [0x48, 0x8b, 0x0d] => [0x48, 0xc7, 0xc1], // mov 0x0(%rip),%rcx -> mov $0x0,%rcx
                    [0x48, 0x8b, 0x15] => [0x48, 0xc7, 0xc2], // mov 0x0(%rip),%rdx -> mov $0x0,%rdx
                    [0x48, 0x8b, 0x35] => [0x48, 0xc7, 0xc6], // mov 0x0(%rip),%rsi -> mov $0x0,%rsi
                    [0x48, 0x8b, 0x3d] => [0x48, 0xc7, 0xc7], // mov 0x0(%rip),%rdi -> mov $0x0,%rdi
                    [0x48, 0x8b, 0x25] => [0x48, 0xc7, 0xc4], // mov 0x0(%rip),%rsp -> mov $0x0,%rsp
                    [0x48, 0x8b, 0x2d] => [0x48, 0xc7, 0xc5], // mov 0x0(%rip),%rbp -> mov $0x0,%rbp
                    [0x4c, 0x8b, 0x05] => [0x49, 0xc7, 0xc0], // mov 0x0(%rip),%r8 -> mov $0x0,%r8
                    [0x4c, 0x8b, 0x0d] => [0x49, 0xc7, 0xc1], // mov 0x0(%rip),%r9 -> mov $0x0,%r9
                    [0x4c, 0x8b, 0x15] => [0x49, 0xc7, 0xc2], // mov 0x0(%rip),%r10 -> mov $0x0,%r10
                    [0x4c, 0x8b, 0x1d] => [0x49, 0xc7, 0xc3], // mov 0x0(%rip),%r11 -> mov $0x0,%r11
                    [0x4c, 0x8b, 0x25] => [0x49, 0xc7, 0xc4], // mov 0x0(%rip),%r12 -> mov $0x0,%r12
                    [0x4c, 0x8b, 0x2d] => [0x49, 0xc7, 0xc5], // mov 0x0(%rip),%r13 -> mov $0x0,%r13
                    [0x4c, 0x8b, 0x35] => [0x49, 0xc7, 0xc6], // mov 0x0(%rip),%r14 -> mov $0x0,%r14
                    [0x4c, 0x8b, 0x3d] => [0x49, 0xc7, 0xc7], // mov 0x0(%rip),%r15 -> mov $0x0,%r15
                    ref x => unreachable!("{:?}", &x),
                };
                buf[..3].as_mut().write_all(&instr).unwrap();
                let value: i32 = (s + a - p).try_into().unwrap();
                buf[3..].as_mut().write_i32::<LittleEndian>(value).unwrap()
            } else {
                let g: i64 = symbol.got_offset().unwrap().try_into().unwrap();
                let value: i32 = (g + got + a - p).try_into().unwrap();
                let buf = writer.section_offset(section_index, rel.r_offset as usize);
                buf[3..].as_mut().write_i32::<LittleEndian>(value).unwrap()
            };
        }
        x => unimplemented!("Relocation {}", r_to_str(x, EM_X86_64)),
    }
}
