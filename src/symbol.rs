use std::{
    hash::{Hash, Hasher},
    path::Path,
};

use goblin::elf64::sym::{Sym, STB_GLOBAL, STB_WEAK};

#[derive(Debug)]
pub struct Symbol<'r> {
    pub sym: Sym,
    reference: &'r Path,
    is_global: bool,
    is_weak: bool,
    in_got: Option<usize>,
    in_plt: Option<usize>,
}

impl<'r> Symbol<'r> {
    pub fn new(sym: Sym, reference: &'r Path) -> Self {
        let bind = sym.st_info >> 4;
        Self {
            sym,
            reference,
            is_global: bind == STB_GLOBAL,
            is_weak: bind == STB_WEAK,
            in_got: None,
            in_plt: None,
        }
    }

    pub const fn is_global(&self) -> bool {
        self.is_global
    }

    pub const fn is_weak(&self) -> bool {
        self.is_weak
    }

    pub const fn reference(&self) -> &Path {
        self.reference
    }

    pub fn set_got_offset(&mut self, offset: usize) {
        self.in_got = Some(offset);
    }

    pub fn set_plt_index(&mut self, index: usize) {
        self.in_plt = Some(index);
    }
}

impl PartialEq for Symbol<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.sym.st_name == other.sym.st_name
    }
}

impl Eq for Symbol<'_> {}

impl Hash for Symbol<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sym.st_name.hash(state);
    }
}
