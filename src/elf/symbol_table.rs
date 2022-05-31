use crate::elf::{Chunk, Section, Symbol};
use crate::serialize::Serialize;

use goblin::elf64::{
    section_header::{
        SectionHeader, SHF_ALLOC, SHN_UNDEF, SHT_DYNSYM, SHT_GNU_HASH, SHT_HASH, SHT_SYMTAB,
    },
    sym::{st_type, Sym, STT_SECTION},
};
use std::ops::Index;
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap},
    mem::size_of,
    path::{Path, PathBuf},
};
use thiserror::Error;

use super::section::{Synthesized, SynthesizedKind};

/// A symbol can be fetched by indexing `symbols` in the following way: `symbols[st_name]`.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum SymbolRef {
    Named(u32),
    // section + number
    Section(u16, usize),
}

impl SymbolRef {
    pub fn st_name(&self) -> u32 {
        if let Self::Named(n) = self {
            *n
        } else {
            // SECTION symbols don't have a name
            0
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("symbol already defined in {0}")]
    AlreadyDefined(PathBuf),
}

#[derive(Debug)]
pub struct SymbolTable<'p> {
    symbols: HashMap<u32, Symbol<'p>>,
    section_syms: HashMap<u16, Vec<Symbol<'p>>>,
    num_locals: usize,
    is_dynamic: bool,
}

impl Default for SymbolTable<'_> {
    fn default() -> Self {
        let mut table = Self {
            symbols: Default::default(),
            section_syms: Default::default(),
            num_locals: 0,
            is_dynamic: false,
        };
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
    pub fn new(is_dynamic: bool) -> Self {
        Self { is_dynamic, ..Default::default() }
    }

    pub fn add_symbol(
        &mut self,
        elf_sym: Sym,
        hash: u32,
        gnu_hash: u32,
        reference: &'p Path,
    ) -> Result<SymbolRef, Error> {
        let st_name = elf_sym.st_name;
        let st_type = st_type(elf_sym.st_info);
        let new_sym = Symbol::new(elf_sym, hash, gnu_hash, reference);
        if st_type == STT_SECTION {
            let len = self
                .section_syms
                .entry(elf_sym.st_shndx)
                .and_modify(|v| v.push(new_sym))
                .or_insert_with(|| vec![new_sym])
                .len()
                - 1;
            return Ok(SymbolRef::Section(elf_sym.st_shndx, len));
        }
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
        Ok(SymbolRef::Named(st_name))
    }

    pub fn get(&self, s: SymbolRef) -> Option<&Symbol<'_>> {
        match s {
            SymbolRef::Named(n) => self.symbols.get(&n),
            SymbolRef::Section(s, i) => self.section_syms.get(&s).map(|s| &s[i]),
        }
    }

    pub fn get_mut(&mut self, s: SymbolRef) -> Option<&mut Symbol<'p>> {
        match s {
            SymbolRef::Named(n) => self.symbols.get_mut(&n),
            SymbolRef::Section(s, i) => self.section_syms.get_mut(&s).map(|s| &mut s[i]),
        }
    }

    pub fn sorted(&self) -> Vec<&Symbol<'p>> {
        let mut syms: Vec<&Symbol<'p>> = self.symbols.values().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(s1, s2));
        syms
    }

    pub fn sorted_mut(&mut self) -> Vec<&mut Symbol<'p>> {
        let mut syms: Vec<&mut Symbol<'p>> = self.symbols.values_mut().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(s1, s2));
        syms
    }

    /// Useful for those cases where we need quick access to a symbol with a given
    ///st_name, and we want to know its index in the final symbol table.
    pub fn sorted_with_indexes(&mut self) -> HashMap<u32, (usize, &mut Symbol<'p>)> {
        let mut syms: Vec<&mut Symbol<'p>> = self.symbols.values_mut().collect();
        syms.sort_by(|s1, s2| sort_symbols_func(s1, s2));
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

    pub fn named(&self) -> &HashMap<u32, Symbol<'_>> {
        &self.symbols
    }

    pub fn named_mut(&mut self) -> &mut HashMap<u32, Symbol<'p>> {
        &mut self.symbols
    }
}

impl<'p> Synthesized<'p> for SymbolTable<'p> {
    fn fill_header(&self, sh: &mut SectionHeader) {
        *sh = SectionHeader {
            sh_type: if self.is_dynamic { SHT_DYNSYM } else { SHT_SYMTAB },
            sh_entsize: size_of::<Sym>() as u64,
            sh_flags: if self.is_dynamic { SHF_ALLOC as u64 } else { 0 },
            sh_addralign: std::mem::align_of::<u64>() as u64,
            ..*sh
        };
    }

    fn expand(&self, sh: &mut Section) {
        sh.add_chunk(self.chunk());
        sh.sh_info = self.num_locals() as u32;
        sh.sh_size = self.total_len() as u64;
    }

    fn finalize(&self, sh: &mut Section) {
        // symbol values might've been patched
        // TODO: don't regenerate chunk again, just patch it in place
        *sh.chunk_mut(0) = self.chunk();
    }

    fn as_ref<'k>(kind: &'k SynthesizedKind<'p>) -> Option<&'k Self> {
        if let SynthesizedKind::SymbolTable(s) = kind {
            Some(s)
        } else {
            None
        }
    }

    fn as_ref_mut<'k>(kind: &'k mut SynthesizedKind<'p>) -> Option<&'k mut Self> {
        if let SynthesizedKind::SymbolTable(s) = kind {
            Some(s)
        } else {
            None
        }
    }
}

fn calculate_bloom(bloom: &mut [u64], hash: u32, elfclass_bits: u32, bloom_shift: u32) {
    let index = ((hash / elfclass_bits) % bloom.len() as u32) as usize;
    bloom[index] |= 1_u64 << (hash % elfclass_bits);
    bloom[index] |= 1_u64 << ((hash >> bloom_shift) % elfclass_bits);
}

impl<'s> Index<SymbolRef> for SymbolTable<'s> {
    type Output = Symbol<'s>;

    fn index(&self, index: SymbolRef) -> &Self::Output {
        match index {
            SymbolRef::Named(n) => &self.symbols[&n],
            SymbolRef::Section(s, i) => &self.section_syms[&s][i],
        }
    }
}

// local before global, then compare by gnu hash
fn sort_symbols_func(s1: &Symbol, s2: &Symbol) -> Ordering {
    let b1 = if s1.is_local() { 0 } else { 1 };
    let b2 = if s2.is_local() { 0 } else { 1 };
    match b1.cmp(&b2) {
        Ordering::Equal => s1.gnu_hash().cmp(&s2.gnu_hash()),
        c => c,
    }
}

#[derive(Default)]
pub struct HashTable {
    pub nbuckets: u32,
    pub nchains: u32,
    pub buckets: Vec<u32>,
    pub chains: Vec<u32>,
}

impl HashTable {
    fn new(buckets: Vec<u32>, chains: Vec<u32>) -> Self {
        Self { nbuckets: buckets.len() as u32, nchains: chains.len() as u32, buckets, chains }
    }

    pub fn size(&self) -> usize {
        size_of::<u32>() * (self.nbuckets as usize + self.nchains as usize + 2)
    }

    pub fn add_symbols(&mut self, symbols: &[&Symbol]) {
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
        *self = Self::new(buckets, chains);
    }
}

impl<'p> Synthesized<'p> for HashTable {
    fn fill_header(&self, sh: &mut SectionHeader) {
        *sh = SectionHeader {
            sh_type: SHT_HASH,
            sh_entsize: std::mem::size_of::<u32>() as u64,
            sh_flags: SHF_ALLOC as u64,
            sh_addralign: std::mem::align_of::<u32>() as u64,

            ..*sh
        }
    }

    fn expand(&self, sh: &mut Section) {
        let mut data = Vec::with_capacity(self.size());
        self.serialize(&mut data);
        sh.sh_size = data.len() as u64;
        sh.add_chunk(data.into());
    }

    fn as_ref<'k>(kind: &'k SynthesizedKind<'p>) -> Option<&'k Self> {
        if let SynthesizedKind::Hash(h) = kind {
            Some(h)
        } else {
            None
        }
    }

    fn as_ref_mut<'k>(kind: &'k mut SynthesizedKind<'p>) -> Option<&'k mut Self> {
        if let SynthesizedKind::Hash(h) = kind {
            Some(h)
        } else {
            None
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
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
        // header + bloom + buckets + table
        4 * size_of::<u32>()
            + self.bloom.len() * size_of::<u64>()
            + self.buckets.len() * size_of::<u32>()
            + self.chains.len() * size_of::<u32>()
    }

    pub fn add_symbols(&mut self, symbols: &[&Symbol]) {
        // should be 32 for elf32, but for now we only support 64 bit anyways
        let elfclass_bits: u32 = 64;
        // mold allocates 12 bits for each symbol in the bloom filter, maybe we should as well
        let bits = (symbols.len() as u32 - 1) * 12;
        let bloom_size = (bits / elfclass_bits).next_power_of_two();
        let bloom_shift = 26;
        let nbuckets: u32 = symbols.len() as u32 / 8 + 1;
        // we always skip the first null symbol. For now, since we don't have
        // any locals in `.dynsym`, we can set this to 1, since we skip 1 symbol only.
        let symbol_offset = 1;
        let symbols = &symbols[symbol_offset..];

        // create a bloom filter
        let mut bloom = vec![0_u64; bloom_size as usize];
        for sym in symbols {
            let hash = sym.gnu_hash();
            calculate_bloom(&mut bloom, hash, elfclass_bits, bloom_shift);
        }

        // prepare the buckets
        let mut buckets = vec![0_u32; nbuckets as usize];
        for (i, sym) in symbols.iter().enumerate() {
            let index = (sym.gnu_hash() % nbuckets) as usize;
            if buckets[index] == 0 {
                buckets[index] = (i + symbol_offset) as u32;
            }
        }

        // prepare the chains
        let mut chains = vec![0_u32; symbols.len()];
        for (i, sym) in symbols.iter().enumerate() {
            // the last value in a chain doesn't have the last bit set, but
            // how do we know if this sym is the last in the chain?
            // since the symbols are sorted by gnu_hash, it means that if
            // this symbol's gnu_hash is different than the gnu_hash of the next symbol,
            // then there is no other symbol that has the same gnu_hash as our
            // current symbol
            if i == symbols.len() - 1
                || sym.gnu_hash() % nbuckets != symbols[i + 1].gnu_hash() % nbuckets
            {
                chains[i] = sym.gnu_hash() | 1;
            } else {
                chains[i] = sym.gnu_hash() & !1;
            }
        }

        *self = GnuHashTable {
            nbuckets,
            buckets,
            sym_offset: symbol_offset as u32,
            bloom_shift,
            bloom_size,
            bloom,
            chains,
        };
    }
}

impl<'p> Synthesized<'p> for GnuHashTable {
    fn fill_header(&self, sh: &mut SectionHeader) {
        *sh = SectionHeader {
            sh_type: SHT_GNU_HASH,
            sh_entsize: std::mem::size_of::<u32>() as u64,
            sh_flags: SHF_ALLOC as u64,
            sh_addralign: std::mem::align_of::<u32>() as u64,
            ..*sh
        }
    }

    fn expand(&self, sh: &mut Section) {
        let mut data = Vec::with_capacity(self.size());
        self.serialize(&mut data);
        sh.sh_size = data.len() as u64;
        sh.add_chunk(data.into());
    }

    fn as_ref<'k>(kind: &'k SynthesizedKind<'p>) -> Option<&'k Self> {
        if let SynthesizedKind::GnuHash(h) = kind {
            Some(h)
        } else {
            None
        }
    }

    fn as_ref_mut<'k>(kind: &'k mut SynthesizedKind<'p>) -> Option<&'k mut Self> {
        if let SynthesizedKind::GnuHash(h) = kind {
            Some(h)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::name::Name;
    use goblin::elf64::sym::STT_FUNC;

    use super::*;

    fn create_symbol(st_name: u32) -> Sym {
        Sym { st_name, st_info: STT_FUNC, ..Default::default() }
    }

    #[test]
    fn gnu_hash_table() {
        let mut table = SymbolTable::new(true);
        let hash1 = Name::from("printf").elf_gnu_hash();
        table.add_symbol(create_symbol(1), 0, hash1, Path::new("")).unwrap();
        let hash2 = Name::from("__libc_start_main").elf_gnu_hash();
        table.add_symbol(create_symbol(2), 0, hash2, Path::new("")).unwrap();
        let sorted = table.sorted();
        let mut ght = GnuHashTable::default();
        ght.add_symbols(&sorted);
        let mut expected_hash_table = GnuHashTable {
            nbuckets: 1,
            sym_offset: 1,
            bloom_size: 1,
            bloom_shift: 26,
            bloom: vec![0],
            buckets: vec![1],
            chains: vec![hash1 & !1, hash2 | 1],
        };
        for hash in [hash1, hash2] {
            calculate_bloom(
                &mut expected_hash_table.bloom,
                hash,
                64,
                expected_hash_table.bloom_shift,
            );
        }
        assert_eq!(ght, expected_hash_table);
    }
}
