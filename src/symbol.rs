use std::{
    hash::{Hash, Hasher},
    path::Path,
};

use goblin::elf64::sym::{Sym, STB_GLOBAL, STB_LOCAL, STB_WEAK};

#[derive(Debug, Clone, Copy)]
pub struct Symbol<'r> {
    pub sym: Sym,
    reference: &'r Path,
    in_got: Option<usize>,
    in_plt: Option<usize>,
    in_got_plt: Option<usize>,
}

impl<'r> Symbol<'r> {
    pub fn new(sym: Sym, reference: &'r Path) -> Self {
        Self { sym, reference, in_got: None, in_plt: None, in_got_plt: None }
    }

    pub const fn st_bind(&self) -> u8 {
        self.sym.st_info >> 4
    }

    pub const fn is_global(&self) -> bool {
        self.st_bind() == STB_GLOBAL
    }

    pub const fn is_weak(&self) -> bool {
        self.st_bind() == STB_WEAK
    }

    pub const fn is_local(&self) -> bool {
        self.st_bind() == STB_LOCAL
    }

    pub const fn reference(&self) -> &Path {
        self.reference
    }

    pub fn got_offset(&self) -> Option<usize> {
        self.in_got
    }

    pub fn got_plt_offset(&self) -> Option<usize> {
        self.in_got_plt
    }

    pub fn plt_index(&self) -> Option<usize> {
        self.in_plt
    }

    pub fn set_got_offset(&mut self, offset: usize) {
        self.in_got = Some(offset);
    }

    pub fn set_got_plt_offset(&mut self, offset: usize) {
        self.in_got_plt = Some(offset);
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

impl std::ops::Deref for Symbol<'_> {
    type Target = Sym;

    fn deref(&self) -> &Self::Target {
        &self.sym
    }
}
