use std::{
    hash::{Hash, Hasher},
    path::Path,
};

use goblin::elf64::sym::{Sym, STB_GLOBAL, STB_WEAK};

#[derive(Debug, Eq)]
pub struct Symbol<'r> {
    name: String,
    old_shndx: u16,
    reference: &'r Path,
    is_global: bool,
    is_weak: bool,
}

impl<'r> Symbol<'r> {
    pub fn new(name: String, sym: &Sym, reference: &'r Path) -> Self {
        let bind = sym.st_info >> 4;
        Self {
            name,
            old_shndx: sym.st_shndx,
            reference,
            is_global: bind == STB_GLOBAL,
            is_weak: bind == STB_WEAK,
        }
    }

    pub const fn is_global(&self) -> bool {
        self.is_global
    }

    pub const fn is_weak(&self) -> bool {
        self.is_weak
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn reference(&self) -> &Path {
        &self.reference
    }
}

impl PartialEq for Symbol<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Hash for Symbol<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}
