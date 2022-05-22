use crate::elf::{chunk::Chunk, SymbolRef};

use goblin::elf64::section_header::{SectionHeader, SHT_NOBITS};
use parking_lot::RwLock;
use std::{any::Any, sync::Arc};

pub type SectionPtr = Arc<RwLock<Section>>;

pub trait Synthesized {
    fn fill_header(&self, sh: &mut SectionHeader);

    fn expand_data(&self, sh: &mut Section);

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct SectionBuilder {
    section: Section,
}

impl SectionBuilder {
    pub fn new(sh: SectionHeader) -> Self {
        Self { section: Section { index: 0, link: None, synthetic: None, sh, chunks: vec![] } }
    }

    pub fn link(mut self, link: SectionPtr) -> Self {
        self.section.link = Some(link);
        self
    }

    pub fn synthetic<T: Synthesized + 'static>(mut self, s: T) -> Self {
        s.fill_header(&mut self.section);
        self.section.synthetic = Some(Box::new(s));
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

    pub fn build(self) -> SectionPtr {
        Arc::new(RwLock::new(self.section))
    }
}

pub struct Section {
    index: usize,
    link: Option<SectionPtr>,
    // TODO: find a more ergonomic way to represent this, without introducing
    // generic parameters, or boxing
    synthetic: Option<Box<dyn Synthesized>>,
    /// The section header of the section.
    sh: SectionHeader,
    /// The data of the section.
    chunks: Vec<Chunk>,
}

impl Section {
    pub fn new(sh: SectionHeader) -> SectionPtr {
        Self::builder(sh).build()
    }

    pub fn builder(sh: SectionHeader) -> SectionBuilder {
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

    pub fn inner<T: Synthesized + 'static>(&self) -> Option<&T> {
        if let Some(s) = &self.synthetic {
            s.as_any().downcast_ref()
        } else {
            None
        }
    }

    pub fn inner_mut<T: Synthesized + 'static>(&mut self) -> Option<&mut T> {
        if let Some(s) = &mut self.synthetic {
            s.as_any_mut().downcast_mut()
        } else {
            None
        }
    }

    pub fn expand_data(&mut self) {
        if let Some(inner) = self.synthetic.take() {
            inner.expand_data(self);
            self.synthetic = Some(inner);
        }
    }

    pub fn finalize(&mut self) {
        let new_link = if let Some(link) = &self.link {
            link.read().index() as u32
        } else {
            return;
        };
        self.sh_link = new_link;
    }
}

impl std::ops::Deref for Section {
    type Target = SectionHeader;

    fn deref(&self) -> &Self::Target {
        &self.sh
    }
}

impl std::ops::DerefMut for Section {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sh
    }
}
