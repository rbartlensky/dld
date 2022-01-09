use crate::elf::chunk::Chunk;

use goblin::elf64::section_header::{SectionHeader, SHT_NOBITS};

pub struct Section {
    /// The section header of the section.
    sh: SectionHeader,
    /// The data of the section.
    chunks: Vec<Chunk>,
}

impl Section {
    pub fn new(sh: SectionHeader) -> Self {
        Self { sh, chunks: vec![] }
    }

    pub fn with_chunk(sh: SectionHeader, data: Vec<u8>) -> Self {
        Self { sh, chunks: vec![Chunk::from(data)] }
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

    pub fn patch_symbol_values(&self, sh_index: u16, table: &mut crate::elf::SymbolTable) {
        let mut base_addr = self.sh_addr;
        for chunk in &self.chunks {
            for symbol_ref in chunk.symbols() {
                if let Some(symbol) = table.get_mut(*symbol_ref) {
                    symbol.st_value += base_addr;
                    symbol.st_shndx = sh_index;
                }
            }
            base_addr += chunk.len() as u64;
        }
    }
}

impl From<SectionHeader> for Section {
    fn from(other: SectionHeader) -> Self {
        Self::new(other)
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
