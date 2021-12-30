use crate::elf::Symbol;
use crate::serialize::Serialize;

use goblin::elf64::{
    section_header::{SectionHeader, SHF_ALLOC, SHN_UNDEF, SHT_HASH},
    sym::Sym,
};
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
        hash: u32,
        reference: &'p Path,
    ) -> Result<Option<SymbolRef>, Error> {
        let st_name = elf_sym.st_name;
        let new_sym = Symbol::new(elf_sym, hash, reference);
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

    pub fn sorted(&mut self) -> Vec<&mut Symbol<'p>> {
        let mut syms: Vec<&mut Symbol<'p>> = self.symbols.values_mut().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(&s1.sym, &s2.sym));
        syms
    }

    pub fn hash_section(sh_name: u32, symbols: &[&mut Symbol]) -> super::Section {
        let nbuckets: u32 = symbols.len() as u32 / 2;
        let mut buckets = vec![0; nbuckets as usize];
        let mut chains = vec![0_u32; symbols.len()];
        for (symbol_index, symbol) in symbols.iter().enumerate() {
            let bucket_index = (symbol.hash() % nbuckets) as usize;
            if buckets[bucket_index] == 0 {
                buckets[bucket_index] = symbol_index as u32;
            } else {
                let mut chain_index = bucket_index;
                let mut next_chain = chains[bucket_index];
                while next_chain != 0 {
                    chain_index = chains[next_chain as usize] as usize;
                    next_chain = chains[chain_index];
                }
                chains[chain_index] = symbol_index as u32;
            }
        }
        let mut data = Vec::with_capacity(nbuckets as usize + chains.len() + 2);
        HashTable::new(buckets, chains).serialize(&mut data);
        super::Section {
            sh: SectionHeader {
                sh_name,
                sh_type: SHT_HASH,
                sh_size: data.len() as u64,
                sh_entsize: std::mem::size_of::<u32>() as u64,
                sh_flags: SHF_ALLOC as u64,
                sh_addralign: std::mem::align_of::<u32>() as u64,
                ..Default::default()
            },
            data,
        }
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

pub struct HashTable {
    pub nbuckets: u32,
    pub nchains: u32,
    pub buckets: Vec<u32>,
    pub chains: Vec<u32>,
}

impl HashTable {
    pub fn new(buckets: Vec<u32>, chains: Vec<u32>) -> Self {
        Self { nbuckets: buckets.len() as u32, nchains: chains.len() as u32, buckets, chains }
    }
}
