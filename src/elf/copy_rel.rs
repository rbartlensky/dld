use std::collections::HashMap;

use goblin::elf64::section_header::{SectionHeader, SHF_ALLOC, SHF_WRITE, SHT_NOBITS};

use super::{
    section::{Synthesized, SynthesizedKind},
    Section, SymbolRef,
};

#[derive(Default)]
pub struct CopyRel {
    // the total size of the section
    size: u64,
    // a mappings from a symbol to a "slot" in the section
    slots: HashMap<SymbolRef, u64>,
}

impl CopyRel {
    pub fn insert(&mut self, sym: SymbolRef, size: u64) -> u64 {
        let offset = self.size;
        self.slots.insert(sym, offset);
        self.size += size;
        offset
    }
}

impl<'p> Synthesized<'p> for CopyRel {
    fn fill_header(&self, sh: &mut SectionHeader) {
        *sh = SectionHeader {
            sh_type: SHT_NOBITS,
            sh_flags: (SHF_ALLOC | SHF_WRITE) as u64,
            sh_addralign: 64,
            ..*sh
        }
    }

    fn expand(&self, sh: &mut Section) {
        sh.sh_size = self.size as u64;
    }

    fn as_ref<'k>(kind: &'k SynthesizedKind<'p>) -> Option<&'k Self> {
        if let SynthesizedKind::CopyRel(s) = kind {
            Some(s)
        } else {
            None
        }
    }

    fn as_ref_mut<'k>(kind: &'k mut SynthesizedKind<'p>) -> Option<&'k mut Self> {
        if let SynthesizedKind::CopyRel(s) = kind {
            Some(s)
        } else {
            None
        }
    }
}
