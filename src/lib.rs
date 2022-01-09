pub mod error;
pub mod elf;
mod name;
mod symbol;
mod serialize;

use error::{Error, ErrorExt, ErrorType};
use goblin::{
    archive::Archive,
    elf::{sym::Sym, Elf},
    elf64::{
        reloc::Rela,
        section_header::{
            SHT_DYNAMIC, SHT_DYNSYM, SHT_REL, SHT_RELA, SHT_SHLIB, SHT_STRTAB, SHT_SYMTAB,
        },
    },
};
use std::{
    collections::{HashMap, HashSet},
    fs::read,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
};

const SKIPPED_SECTIONS: &[u32] =
    &[SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB, SHT_RELA, SHT_DYNAMIC, SHT_REL, SHT_SHLIB];

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

pub struct Input<'o> {
    path: &'o Path,
    data: Vec<u8>,
}

impl<'o> Input<'o> {
    fn process<'e>(&'e self, writer: &mut elf::Writer<'o>) -> Result<(), Error<'o>> {
        let elf = Elf::parse(&self.data).map_path_err(self.path)?;
        if elf.is_object_file() {
            Ok(process_elf_object(self.path, &self.data, elf, writer)?)
        } else {
            Ok(())
        }
    }
}

fn process_elf_object<'e, 'o>(
    path: &'o Path,
    data: &'e [u8],
    elf: Elf<'e>,
    writer: &mut elf::Writer<'o>,
) -> Result<(), Error<'o>> {
    let mut section_relocations = HashMap::new();
    let mut symbols = HashMap::new();
    for (i, section) in elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, sh)| !SKIPPED_SECTIONS.contains(&sh.sh_type))
    {
        let name = get_section_name(&elf, section.sh_name).map_path_err(path)?;
        let section_ref =
            writer.push_section(name.to_owned(), section, section.file_range().map(|r| &data[r]));
        log::trace!("Section '{}:{}' of {:?} mapped to {:?}", i, name, path, section_ref);
        section_relocations.insert(i, section_ref);
    }
    for symbol in &elf.syms {
        let name = get_symbol_name(&elf, symbol.st_name).map_path_err(path)?;
        let sec_ref = section_relocations.get(&(symbol.st_shndx as usize));
        let symbol_ref =
            writer.add_symbol(symbol.into(), sec_ref.copied(), name, path).map_path_err(path)?;
        if let Some(sym) = symbol_ref {
            symbols.insert(Symbol(symbol), sym);
        }
    }
    for (section_index, rels) in &elf.shdr_relocs {
        for rel in rels.iter().filter(|r| r.r_sym != 0) {
            let symbol = &elf.syms.get(rel.r_sym as usize).unwrap();
            let index = if let Some(sec) = section_relocations.get(&(section_index - 1)) {
                *sec
            } else {
                continue;
            };
            let symbol = if let Some(sym) = symbols.get(&Symbol(*symbol)) {
                sym
            } else {
                continue;
            };
            let rela = Rela {
                r_offset: rel.r_offset,
                r_info: ((rel.r_sym << 32) + rel.r_type as usize) as u64,
                r_addend: rel.r_addend.unwrap_or_default() as i64,
            };
            writer.add_relocation(rela, *symbol, index).map_path_err(path)?;
        }
    }
    Ok(())
}

pub struct Linker {
    pub options: crate::elf::Options,
    pub objects: HashSet<PathBuf>,
    pub archives: HashSet<PathBuf>,
}

impl Linker {
    fn find_undefined_symbols_in_libs<'o>(
        &'o self,
        symbols: Vec<elf::SymbolRef>,
        writer: &mut elf::Writer<'o>,
    ) -> Result<Vec<elf::SymbolRef>, Error<'o>> {
        let mut undefines =
            symbols.into_iter().map(|s| (s, false)).collect::<HashMap<elf::SymbolRef, bool>>();
        for (lib, _) in &self.options.shared_libs {
            let path = lib.as_path();
            let data = read(path).map_path_err(path)?;
            let elf = Elf::parse(&data).unwrap();
            for entry in undefines.iter_mut().filter(|(_, v)| !**v) {
                let name = writer.symbol_name(*entry.0).to_string();
                for sym in &elf.dynsyms {
                    let inner_name = get_dyn_symbol_name(&elf, sym.st_name).map_path_err(path)?;
                    if name == inner_name {
                        *entry.1 = true;
                        writer
                            .add_dyn_symbol(sym.into(), None, inner_name, path)
                            .map_path_err(path)?;
                        writer.add_needed(path.file_name().unwrap().to_str().unwrap());
                    }
                }
            }
            undefines.retain(|_, found| !*found);
        }
        Ok(undefines.into_iter().map(|(k, _)| k).collect())
    }

    fn process_archives_containing<'o>(
        &'o self,
        symbols: Vec<elf::SymbolRef>,
        writer: &mut elf::Writer<'o>,
    ) -> Result<(), Error<'o>> {
        let mut undefines =
            symbols.into_iter().map(|s| (s, false)).collect::<HashMap<elf::SymbolRef, bool>>();
        for ar in &self.archives {
            let path = ar.as_path();
            let data = read(path).map_path_err(path)?;
            let ar = Archive::parse(&data).map_path_err(path)?;
            let mut members = HashSet::new();
            for entry in &mut undefines {
                let name = writer.symbol_name(*entry.0);
                if let Some(member) = ar.member_of_symbol(name) {
                    *entry.1 = true;
                    members.insert(member);
                }
            }
            for member in members {
                let object = ar.get(member).unwrap();
                let object_data =
                    &data[(object.offset as usize)..(object.offset as usize + object.size())];
                let elf = Elf::parse(object_data).unwrap();
                process_elf_object(path, object_data, elf, writer)?;
            }
            undefines.retain(|_, found| !*found);
        }
        Ok(())
    }

    pub fn link(&self) -> Result<(), Error<'_>> {
        let mut writer =
            elf::Writer::new(&self.options).map_path_err(self.options.output.as_path())?;
        let objects = self
            .objects
            .iter()
            .map(|p| {
                let path = p.as_path();
                let data = read(path).map_path_err(path)?;
                Ok(Input { data, path })
            })
            .collect::<Result<Vec<Input>, Error<'_>>>()?;
        let _ = objects
            .iter()
            .map(|o| o.process(&mut writer))
            .collect::<Result<Vec<()>, Error<'_>>>()?;
        let undefined = writer.undefined_symbols();
        let undefined = self.find_undefined_symbols_in_libs(undefined, &mut writer)?;
        self.process_archives_containing(undefined, &mut writer)?;
        writer.compute_sections();
        let undefined = writer.undefined_symbols();
        if !undefined.is_empty() {
            let names =
                undefined.iter().map(|u| writer.symbol_name(*u).to_string()).collect::<Vec<_>>();
            return Err(ErrorType::Other(format_list(&names)))
                .map_path_err(self.options.output.as_path());
        }
        writer.write_to_disk();
        Ok(())
    }
}

fn get_section_name<'e>(elf: &Elf<'e>, index: usize) -> Result<&'e str, String> {
    elf.shdr_strtab.get_at(index).ok_or_else(|| "Symbol not found in strtab.".to_string())
}

fn get_symbol_name<'e>(elf: &Elf<'e>, index: usize) -> Result<&'e str, String> {
    elf.strtab.get_at(index).ok_or_else(|| "Symbol not found in strtab.".to_string())
}

fn get_dyn_symbol_name<'e>(elf: &Elf<'e>, index: usize) -> Result<&'e str, String> {
    elf.dynstrtab.get_at(index).ok_or_else(|| "Symbol not found in strtab.".to_string())
}

fn format_list(v: &[String]) -> String {
    let mut s = String::from("[");
    s += &v.join(", ");
    s += "]";
    s
}
