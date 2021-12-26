use crate::elf::Symbol;

use goblin::elf64::{section_header::SHN_UNDEF, sym::Sym};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap},
    ops::Deref,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// A symbol can be fetched by indexing `symbols` in the following way: `symbols[st_name][index]`.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SymbolRef {
    pub st_name: u32,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("symbol already defined in {0}")]
    AlreadyDefined(PathBuf),
}

#[derive(Default)]
pub struct SymbolTable<'p> {
    symbols: HashMap<u32, Symbol<'p>>,
}

impl<'p> SymbolTable<'p> {
    pub fn add_symbol(
        &mut self,
        elf_sym: Sym,
        reference: &'p Path,
    ) -> Result<Option<SymbolRef>, Error> {
        let st_name = elf_sym.st_name;
        let new_sym = Symbol::new(elf_sym, reference);
        match self.symbols.entry(st_name) {
            Entry::Occupied(mut s) => {
                let old_sym = s.get_mut();
                // we found another definition of this global symbol
                if old_sym.is_global()
                    && new_sym.is_global()
                    && old_sym.st_shndx != SHN_UNDEF as u16
                    && new_sym.st_shndx != SHN_UNDEF as u16
                {
                    log::trace!(
                        "Old defition: {:#?} vs new definition: {:#?}",
                        old_sym.sym,
                        new_sym.sym
                    );
                    return Err(Error::AlreadyDefined(old_sym.reference().into()));
                }
                if !old_sym.higher_bind_than(new_sym) {
                    old_sym.st_info = new_sym.st_info;
                    old_sym.st_other = new_sym.st_other;
                    old_sym.st_shndx = new_sym.st_shndx;
                    old_sym.st_value = new_sym.st_value;
                    old_sym.st_size = new_sym.st_size;
                } else if old_sym.st_shndx == SHN_UNDEF as u16 {
                    old_sym.st_shndx = new_sym.st_shndx;
                }
            }
            Entry::Vacant(v) => {
                v.insert(new_sym);
            }
        };
        Ok(Some(SymbolRef { st_name }))
    }

    pub fn get(&self, s: SymbolRef) -> Option<&Symbol<'_>> {
        self.symbols.get(&s.st_name)
    }

    pub fn get_mut(&mut self, s: SymbolRef) -> Option<&mut Symbol<'p>> {
        self.symbols.get_mut(&s.st_name)
    }

    pub fn sorted(&mut self) -> Vec<&mut Sym> {
        let mut syms: Vec<&mut Sym> = self.symbols.values_mut().map(|s| &mut s.sym).collect();
        syms.sort_by(|s1, s2| sort_symbols_func(s1, s2));
        syms
    }
}

impl<'p> Deref for SymbolTable<'p> {
    type Target = HashMap<u32, Symbol<'p>>;

    fn deref(&self) -> &Self::Target {
        &self.symbols
    }
}

fn st_type(st_info: u8) -> u8 {
    st_info & 0xf
}

fn st_bind(st_info: u8) -> u8 {
    st_info >> 4
}

// local before global, notype before other types
fn sort_symbols_func(s1: &Sym, s2: &Sym) -> Ordering {
    let b1 = st_bind(s1.st_info);
    let b2 = st_bind(s2.st_info);
    let t1 = st_type(s1.st_info);
    let t2 = st_type(s2.st_info);
    match b1.cmp(&b2) {
        Ordering::Equal => t1.cmp(&t2),
        c => c,
    }
}
