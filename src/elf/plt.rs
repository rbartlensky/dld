use std::{collections::HashMap, mem::size_of};

use crate::elf::{section::Synthesized, Section, SymbolRef};
use goblin::elf64::section_header::{SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS};

const PLT_ENTRY_SIZE: usize = 16;

#[derive(Default)]
pub struct Plt {
    /// Mapping from symbols to plt slots (starting from 0)
    inner: HashMap<SymbolRef, usize>,
}

impl Plt {
    pub fn insert(&mut self, sym_ref: SymbolRef) -> usize {
        let len = self.inner.len();
        *self.inner.entry(sym_ref).or_insert(len)
    }
}

impl Synthesized for Plt {
    fn fill_header(&self, sh: &mut SectionHeader) {
        sh.sh_flags = (SHF_ALLOC | SHF_EXECINSTR) as u64;
        sh.sh_type = SHT_PROGBITS;
        sh.sh_addralign = size_of::<u64>() as u64;
    }

    fn expand_data(&self, section: &mut Section) {
        let size = (self.inner.len() + 1) * PLT_ENTRY_SIZE;
        section.sh_size = size as u64;

        // at this point we still don't know where our .got entries, as such
        // we patch the addresses later
        let mut plt_chunk = Vec::with_capacity(size);
        let header = [
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00, // pushq  0x0(%rip)
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x90, 0x90, 0x90, 0x90, // nop nop nop nop
        ];
        plt_chunk.extend(header);

        let entry = [
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x68, 0x00, 0x00, 0x00, 0x00, // push   x00000000
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmpq   0x0
        ];
        for _ in 0..self.inner.len() {
            plt_chunk.extend(&entry);
        }

        section.add_chunk(plt_chunk.into());
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
