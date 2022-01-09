use crate::elf::{Chunk, Symbol};
use crate::serialize::Serialize;

use goblin::elf64::{
    section_header::{
        SectionHeader, SHF_ALLOC, SHN_UNDEF, SHT_DYNSYM, SHT_GNU_HASH, SHT_HASH, SHT_SYMTAB,
    },
    sym::Sym,
};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap},
    mem::size_of,
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

pub struct SymbolTable<'p> {
    symbols: HashMap<u32, Symbol<'p>>,
    num_locals: usize,
}

impl Default for SymbolTable<'_> {
    fn default() -> Self {
        let mut table = Self { symbols: Default::default(), num_locals: 0 };
        table
            .add_symbol(
                Sym { st_shndx: SHN_UNDEF as u16, ..Default::default() },
                0,
                0,
                Path::new(""),
            )
            .unwrap();
        table
    }
}

impl<'p> SymbolTable<'p> {
    pub fn new(sh_name: u32, is_dynamic: bool) -> (Self, SectionHeader) {
        (
            Default::default(),
            SectionHeader {
                sh_name,
                sh_type: if is_dynamic { SHT_DYNSYM } else { SHT_SYMTAB },
                sh_entsize: size_of::<Sym>() as u64,
                sh_flags: SHF_ALLOC as u64,
                sh_addralign: std::mem::align_of::<u64>() as u64,
                ..Default::default()
            },
        )
    }

    pub fn add_symbol(
        &mut self,
        elf_sym: Sym,
        hash: u32,
        gnu_hash: u32,
        reference: &'p Path,
    ) -> Result<Option<SymbolRef>, Error> {
        let st_name = elf_sym.st_name;
        let new_sym = Symbol::new(elf_sym, hash, gnu_hash, reference);
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
                if new_sym.is_local() {
                    self.num_locals += 1;
                }
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

    pub fn sorted(&self) -> Vec<&Symbol<'p>> {
        let mut syms: Vec<&Symbol<'p>> = self.symbols.values().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(&s1, &s2));
        syms
    }

    pub fn sorted_mut(&mut self) -> Vec<&mut Symbol<'p>> {
        let mut syms: Vec<&mut Symbol<'p>> = self.symbols.values_mut().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(&s1, &s2));
        syms
    }

    /// Useful for those cases where we need quick access to a symbol with a given
    ///st_name, and we want to know its index in the final symbol table.
    pub fn sorted_with_indexes(&mut self) -> HashMap<u32, (usize, &mut Symbol<'p>)> {
        let mut syms: Vec<&mut Symbol<'p>> = self.symbols.values_mut().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(&s1, &s2));
        syms.into_iter().enumerate().map(|(i, s)| (s.st_name, (i, s))).collect()
    }

    pub fn total_len(&self) -> usize {
        self.symbols.len() * size_of::<Sym>()
    }

    pub fn chunk(&self) -> Chunk {
        let mut data = Vec::with_capacity(self.total_len());
        for sym in self.sorted() {
            sym.serialize(&mut data);
        }
        data.into()
    }

    pub fn num_locals(&self) -> usize {
        self.num_locals
    }

    pub fn hash_section(sh_name: u32, symbols: &[&Symbol]) -> super::Section {
        let nbuckets: u32 = symbols.len() as u32 / 2 + 1;
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
        super::Section::with_chunk(
            SectionHeader {
                sh_name,
                sh_type: SHT_HASH,
                sh_size: data.len() as u64,
                sh_entsize: std::mem::size_of::<u32>() as u64,
                sh_flags: SHF_ALLOC as u64,
                sh_addralign: std::mem::align_of::<u32>() as u64,
                ..Default::default()
            },
            data,
        )
    }

    pub fn gnu_hash_section(sh_name: u32, symbols: &[&Symbol]) -> super::Section {
        // should be 32 for elf32, but for now we only support 64 bit anyways
        let elfclass_bits = 64;
        // TODO: figure out a good numbers here
        let bloom_size = 5;
        let bloom_shift = 5;
        let nbuckets: u32 = symbols.len() as u32 / 2 + 1;
        // we always skip the first null symbol. For now, since we don't have
        // any locals in `.dynsym`, we can set this to 1, since we skip 1 symbol only.
        let symbol_offset = 1;

        // create a bloom filter
        let mut bloom = vec![0_u64; bloom_size as usize];
        for sym in &symbols[symbol_offset..] {
            let hash = sym.gnu_hash();
            let index = ((sym.gnu_hash() / elfclass_bits) % bloom_size) as usize;
            bloom[index] |= 1_u64 << (hash % elfclass_bits);
            bloom[index] |= 1_u64 << ((hash >> bloom_shift) % elfclass_bits);
        }

        // prepare the buckets
        let mut buckets = vec![0_u32; nbuckets as usize];
        for (i, sym) in symbols.iter().enumerate().skip(symbol_offset) {
            let index = (sym.gnu_hash() % nbuckets) as usize;
            if buckets[index] == 0 {
                buckets[index] = i as u32;
            }
        }

        // prepare the chains
        let mut chains = vec![0_u32; symbols.len()];
        for (i, sym) in symbols.iter().enumerate().skip(symbol_offset) {
            // the last value in a chain doesn't have the last bit set, but
            // how do we know if this sym is the last in the chain?
            // since the symbols are sorted by gnu_hash, it means that if
            // this symbol's gnu_hash is different than the gnu_hash of the next symbol,
            // then there is no other symbol that has the same gnu_hash as our
            // current symbol
            let value = if i == symbols.len() - 1 || sym.gnu_hash() != symbols[i + 1].gnu_hash() {
                sym.gnu_hash() | 1
            } else {
                sym.gnu_hash() & !1
            };
            chains.push(value);
        }

        let ght = GnuHashTable {
            nbuckets,
            buckets,
            sym_offset: symbol_offset as u32,
            bloom_shift,
            bloom_size,
            bloom,
            chains,
        };
        let mut data = Vec::with_capacity(ght.size());
        ght.serialize(&mut data);
        super::Section::with_chunk(
            SectionHeader {
                sh_name,
                sh_type: SHT_GNU_HASH,
                sh_size: data.len() as u64,
                sh_entsize: std::mem::size_of::<u32>() as u64,
                sh_flags: SHF_ALLOC as u64,
                sh_addralign: std::mem::align_of::<u32>() as u64,
                ..Default::default()
            },
            data,
        )
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
fn sort_symbols_func(s1: &Symbol, s2: &Symbol) -> Ordering {
    let b1 = st_bind(s1.st_info);
    let b2 = st_bind(s2.st_info);
    let t1 = st_type(s1.st_info);
    let t2 = st_type(s2.st_info);
    match b1.cmp(&b2) {
        Ordering::Equal => match s1.gnu_hash().cmp(&s2.gnu_hash()) {
            Ordering::Equal => t1.cmp(&t2),
            c => c,
        },
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

pub struct GnuHashTable {
    pub nbuckets: u32,
    pub buckets: Vec<u32>,
    pub sym_offset: u32,
    pub bloom_size: u32,
    pub bloom_shift: u32,
    pub bloom: Vec<u64>,
    pub chains: Vec<u32>,
}

impl GnuHashTable {
    pub fn size(&self) -> usize {
        (self.nbuckets as usize + 4 + self.chains.len()) * size_of::<u32>()
            + self.bloom_size as usize * size_of::<u64>()
    }
}
