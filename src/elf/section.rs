use crate::elf::{
    chunk::Chunk,
    plt::Plt,
    string_table::StringTable,
    symbol_table::{GnuHashTable, HashTable},
    SymbolRef,
};

use goblin::elf64::section_header::{SectionHeader, SHT_NOBITS};
use parking_lot::RwLock;
use std::sync::Arc;

use super::SymbolTable;

pub type SectionPtr<'p> = Arc<RwLock<Section<'p>>>;

pub trait Synthesized<'p> {
    fn fill_header(&self, sh: &mut SectionHeader);

    fn expand(&self, sh: &mut Section);

    fn finalize(&self, _sh: &mut Section) {}

    fn as_ref<'k>(kind: &'k SynthesizedKind<'p>) -> Option<&'k Self>;

    fn as_ref_mut<'k>(kind: &'k mut SynthesizedKind<'p>) -> Option<&'k mut Self>;
}

pub struct SectionBuilder<'p> {
    section: Section<'p>,
}

impl<'p> SectionBuilder<'p> {
    pub fn new(sh: SectionHeader) -> Self {
        Self { section: Section { index: 0, link: None, synthetic: None, sh, chunks: vec![] } }
    }

    pub fn link(mut self, link: SectionPtr<'p>) -> Self {
        self.section.link = Some(link);
        self
    }

    pub fn synthetic<T: Into<SynthesizedKind<'p>>>(mut self, s: T) -> Self {
        let s = s.into();
        s.fill_header(&mut self.section);
        self.section.synthetic = Some(s);
        self
    }

    pub fn with_chunk(mut self, data: Vec<u8>) -> Self {
        self.section.chunks.push(data.into());
        self
    }

    pub fn index(mut self, index: usize) -> Self {
        self.section.index = index;
        self
    }

    pub fn build(self) -> SectionPtr<'p> {
        Arc::new(RwLock::new(self.section))
    }
}

pub enum SynthesizedKind<'p> {
    Plt(Plt),
    StringTable(StringTable),
    Hash(HashTable),
    GnuHash(GnuHashTable),
    SymbolTable(SymbolTable<'p>),
}

impl From<Plt> for SynthesizedKind<'_> {
    fn from(p: Plt) -> Self {
        Self::Plt(p)
    }
}

impl From<StringTable> for SynthesizedKind<'_> {
    fn from(p: StringTable) -> Self {
        Self::StringTable(p)
    }
}

impl From<HashTable> for SynthesizedKind<'_> {
    fn from(p: HashTable) -> Self {
        Self::Hash(p)
    }
}

impl From<GnuHashTable> for SynthesizedKind<'_> {
    fn from(p: GnuHashTable) -> Self {
        Self::GnuHash(p)
    }
}

impl<'p> From<SymbolTable<'p>> for SynthesizedKind<'p> {
    fn from(p: SymbolTable<'p>) -> Self {
        Self::SymbolTable(p)
    }
}

impl<'p> Synthesized<'p> for SynthesizedKind<'p> {
    fn fill_header(&self, sh: &mut SectionHeader) {
        use SynthesizedKind::*;

        match self {
            Plt(p) => p.fill_header(sh),
            StringTable(s) => s.fill_header(sh),
            Hash(h) => h.fill_header(sh),
            GnuHash(h) => h.fill_header(sh),
            SymbolTable(s) => s.fill_header(sh),
        }
    }

    fn expand(&self, sh: &mut Section) {
        use SynthesizedKind::*;

        match self {
            Plt(p) => p.expand(sh),
            StringTable(s) => s.expand(sh),
            Hash(h) => h.expand(sh),
            GnuHash(h) => h.expand(sh),
            SymbolTable(s) => s.expand(sh),
        }
    }

    fn finalize(&self, sh: &mut Section) {
        use SynthesizedKind::*;

        match self {
            Plt(p) => p.finalize(sh),
            StringTable(s) => s.finalize(sh),
            Hash(h) => h.finalize(sh),
            GnuHash(h) => h.finalize(sh),
            SymbolTable(s) => s.finalize(sh),
        }
    }

    fn as_ref(_kind: &SynthesizedKind<'p>) -> Option<&'p Self> {
        None
    }

    fn as_ref_mut(_kind: &mut SynthesizedKind<'p>) -> Option<&'p mut Self> {
        None
    }
}

pub struct Section<'p> {
    index: usize,
    link: Option<SectionPtr<'p>>,
    // TODO: can we go further and get rid of the `Any` casts?
    synthetic: Option<SynthesizedKind<'p>>,
    /// The section header of the section.
    sh: SectionHeader,
    /// The data of the section.
    chunks: Vec<Chunk>,
}

impl<'p> Section<'p> {
    pub fn new(sh: SectionHeader) -> SectionPtr<'p> {
        Self::builder(sh).build()
    }

    pub fn builder(sh: SectionHeader) -> SectionBuilder<'p> {
        SectionBuilder::new(sh)
    }

    pub fn add_chunk(&mut self, chunk: Chunk) -> usize {
        self.chunks.push(chunk);
        self.chunks.len() - 1
    }

    pub fn last_chunk_index(&self) -> usize {
        self.chunks.len() - 1
    }

    pub fn chunk_mut(&mut self, i: usize) -> &mut Chunk {
        &mut self.chunks[i]
    }

    pub fn size_on_disk(&self) -> u64 {
        if self.sh.sh_type != SHT_NOBITS {
            self.sh.sh_size
        } else {
            0
        }
    }

    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks[..]
    }

    pub fn chunks_mut(&mut self) -> &mut [Chunk] {
        &mut self.chunks[..]
    }

    pub fn set_address(&mut self, sh_addr: u64) {
        self.sh_addr = sh_addr;
        let mut base_addr = self.sh_addr;
        for chunk in &mut self.chunks {
            chunk.set_address(base_addr);
            base_addr += chunk.len() as u64;
        }
    }

    pub fn patch_symbol_values(&mut self, table: &mut crate::elf::SymbolTable) {
        let mut base_addr = self.sh_addr;
        let sh_index = self.index as u16;
        for chunk in &self.chunks {
            for symbol_ref in chunk.symbols().iter() {
                if let Some(symbol) = table.get_mut(*symbol_ref) {
                    symbol.st_shndx = sh_index;
                    if matches!(symbol_ref, SymbolRef::Section(..)) {
                        symbol.st_value = base_addr;
                    } else {
                        symbol.st_value += base_addr;
                    }
                }
            }
            base_addr += chunk.len() as u64;
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn set_index(&mut self, index: usize) {
        self.index = index;
    }

    pub fn inner<T: Synthesized<'p>>(&self) -> Option<&T> {
        if let Some(s) = &self.synthetic {
            T::as_ref(s)
        } else {
            None
        }
    }

    pub fn inner_mut<T: Synthesized<'p>>(&mut self) -> Option<&mut T> {
        if let Some(s) = &mut self.synthetic {
            T::as_ref_mut(s)
        } else {
            None
        }
    }

    pub fn expand(&mut self) {
        if let Some(inner) = self.synthetic.take() {
            inner.expand(self);
            self.synthetic = Some(inner);
        }
    }

    pub fn finalize(&mut self) {
        if let Some(inner) = self.synthetic.take() {
            inner.finalize(self);
            self.synthetic = Some(inner);
        }
        let new_link = if let Some(link) = &self.link {
            link.read().index() as u32
        } else {
            return;
        };
        self.sh_link = new_link;
    }
}

impl std::ops::Deref for Section<'_> {
    type Target = SectionHeader;

    fn deref(&self) -> &Self::Target {
        &self.sh
    }
}

impl std::ops::DerefMut for Section<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sh
    }
}
