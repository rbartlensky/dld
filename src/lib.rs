pub mod error;
pub mod elf;
mod name;
mod symbol;
mod serialize;
mod utils;

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

pub struct Input<'p, 'd> {
    path: &'p Path,
    data: &'d [u8],
}

pub struct ElfObject<'i, 'p, 'd, 'e> {
    input: &'i Input<'p, 'd>,
    elf: Elf<'e>,
    section_relocations: HashMap<usize, elf::SectionRef<'p>>,
    symbols: HashMap<Symbol, elf::SymbolRef>,
}

impl<'p, 'd> Input<'p, 'd> {
    fn to_elf_object<'i>(&'i self) -> Result<Option<ElfObject<'i, 'p, '_, 'i>>, Error<'p>> {
        let elf = Elf::parse(self.data).map_path_err(self.path)?;
        Ok(if elf.is_object_file() { Some(ElfObject::new(self, elf)) } else { None })
    }
}

impl<'i, 'p, 'd, 'e> ElfObject<'i, 'p, 'd, 'e> {
    pub fn new(input: &'i Input<'p, 'd>, elf: Elf<'e>) -> Self {
        Self { input, elf, section_relocations: Default::default(), symbols: Default::default() }
    }

    pub fn process_sections(&mut self, writer: &mut elf::Writer<'p>) -> Result<(), Error<'p>> {
        for (i, section) in self
            .elf
            .section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| !SKIPPED_SECTIONS.contains(&sh.sh_type))
        {
            let name =
                get_section_name(&self.elf, section.sh_name).map_path_err(self.input.path)?;
            let section_ref = writer.push_section(
                name.to_owned(),
                section,
                section.file_range().map(|r| &self.input.data[r]),
            );
            log::trace!(
                "Section '{}:{}' of {:?} mapped to {:?}",
                i,
                name,
                self.input.path,
                section_ref,
            );
            self.section_relocations.insert(i, section_ref);
        }
        Ok(())
    }

    pub fn process_symbols(&mut self, writer: &mut elf::Writer<'p>) -> Result<(), Error<'p>> {
        let path = &self.input.path;
        let elf = &self.elf;
        for symbol in &elf.syms {
            let name = get_symbol_name(elf, symbol.st_name).map_path_err(path)?;
            let sec_ref = self.section_relocations.get(&(symbol.st_shndx as usize));
            let symbol_ref = writer
                .add_symbol(symbol.into(), sec_ref.cloned(), name, path)
                .map_path_err(path)?;
            if let Some(sym) = symbol_ref {
                self.symbols.insert(Symbol(symbol), sym);
            }
        }
        Ok(())
    }

    pub fn process_relocations(&self, writer: &mut elf::Writer<'p>) -> Result<(), Error<'p>> {
        let elf = &self.elf;
        for (section_index, rels) in &elf.shdr_relocs {
            for rel in rels.iter().filter(|r| r.r_sym != 0) {
                let symbol = &elf.syms.get(rel.r_sym as usize).unwrap();
                let index = if let Some(sec) = self.section_relocations.get(&(section_index - 1)) {
                    sec.clone()
                } else {
                    continue;
                };
                let symbol = if let Some(sym) = self.symbols.get(&Symbol(*symbol)) {
                    sym
                } else {
                    continue;
                };
                let rela = Rela {
                    r_offset: rel.r_offset,
                    r_info: ((rel.r_sym << 32) + rel.r_type as usize) as u64,
                    r_addend: rel.r_addend.unwrap_or_default() as i64,
                };
                writer.add_relocation(rela, *symbol, index).map_path_err(self.input.path)?;
            }
        }
        Ok(())
    }
}

pub struct Linker {
    pub options: crate::elf::Options,
    pub objects: Vec<PathBuf>,
    pub archives: HashSet<PathBuf>,
}

impl Linker {
    fn find_undefined_symbols_in_libs<'o>(
        &'o self,
        symbols: &[elf::SymbolRef],
        writer: &mut elf::Writer<'o>,
    ) -> Result<Vec<elf::SymbolRef>, Error<'o>> {
        let mut undefines =
            symbols.iter().map(|s| (*s, false)).collect::<HashMap<elf::SymbolRef, bool>>();
        for (lib, _) in &self.options.shared_libs {
            let path = lib.as_path();
            let data = read(path).map_path_err(path)?;
            let elf = Elf::parse(&data).unwrap();
            for entry in undefines.iter_mut().filter(|(_, v)| !**v) {
                let name = if let Some(name) = writer.symbol_name(*entry.0) {
                    name.to_string()
                } else {
                    continue;
                };
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
        symbols: &[elf::SymbolRef],
        writer: &mut elf::Writer<'o>,
    ) -> Result<Vec<elf::SymbolRef>, Error<'o>> {
        let mut undefines =
            symbols.iter().map(|s| (*s, false)).collect::<HashMap<elf::SymbolRef, bool>>();
        for ar in &self.archives {
            let path = ar.as_path();
            let data = read(path).map_path_err(path)?;
            let ar = Archive::parse(&data).map_path_err(path)?;
            let mut members = HashSet::new();
            for entry in &mut undefines {
                let name = if let Some(name) = writer.symbol_name(*entry.0) {
                    name
                } else {
                    continue;
                };
                if let Some(member) = ar.member_of_symbol(&*name) {
                    *entry.1 = true;
                    members.insert(member);
                }
            }
            for member in members {
                let object = ar.get(member).unwrap();
                let object_data =
                    &data[(object.offset as usize)..(object.offset as usize + object.size())];
                let input = Input { path, data: object_data };
                let mut elf = input.to_elf_object()?.unwrap();
                elf.process_sections(writer)?;
                elf.process_symbols(writer)?;
                elf.process_relocations(writer)?;
            }
            undefines.retain(|_, found| !*found);
        }
        Ok(undefines.into_iter().map(|(k, _)| k).collect())
    }

    pub fn link(&self) -> Result<(), Error<'_>> {
        let mut writer =
            elf::Writer::new(&self.options).map_path_err(self.options.output.as_path())?;
        let mut elf_data = Vec::with_capacity(self.objects.len());
        for obj in &self.objects {
            let path = obj.as_path();
            let data = read(path).map_path_err(path)?;
            elf_data.push(data);
        }
        let inputs = elf_data
            .iter()
            .zip(self.objects.iter())
            .map(|(data, path)| Ok(Input { data, path }))
            .collect::<Result<Vec<Input>, Error<'_>>>()?;
        let mut elfs = Vec::with_capacity(inputs.len());
        for input in &inputs {
            if let Some(mut elf) = input.to_elf_object()? {
                elf.process_sections(&mut writer)?;
                elfs.push(elf);
            };
        }
        for elf in &mut elfs {
            elf.process_symbols(&mut writer)?;
            elf.process_relocations(&mut writer)?;
        }
        let mut undefined = writer.undefined_symbols();
        loop {
            let undefined_next = self.find_undefined_symbols_in_libs(&undefined, &mut writer)?;
            let undefined_next = self.process_archives_containing(&undefined_next, &mut writer)?;
            // if the length doesn't change, it means we haven't found any of our symbols
            if undefined.len() == undefined_next.len() {
                break;
            } else {
                undefined = writer.undefined_symbols();
            }
        }
        writer.compute_sections();
        let undefined = writer.undefined_symbols();
        if !undefined.is_empty() {
            let names = undefined
                .iter()
                .filter_map(|u| writer.symbol_name(*u).map(|s| s.to_string()))
                .collect::<Vec<_>>();
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
