use crate::elf::SymbolRef;

use std::{
    hash::{Hash, Hasher},
    path::Path,
};

use goblin::elf64::{
    section_header::SHN_UNDEF,
    sym::{Sym, STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_OBJECT, STT_TLS},
};

#[derive(Debug, Clone, Copy)]
pub struct Symbol<'r> {
    pub sym: Sym,
    hash: u32,
    gnu_hash: u32,
    reference: &'r Path,
    in_got: Option<usize>,
    in_plt: Option<usize>,
    in_got_plt: Option<usize>,
    relocation_offset: Option<usize>,
    dynamic: Option<SymbolRef>,
}

impl<'r> Symbol<'r> {
    pub fn new(sym: Sym, hash: u32, gnu_hash: u32, reference: &'r Path) -> Self {
        Self {
            sym,
            reference,
            hash,
            gnu_hash,
            in_got: None,
            in_plt: None,
            in_got_plt: None,
            relocation_offset: None,
            dynamic: None,
        }
    }

    pub const fn st_bind(&self) -> u8 {
        self.sym.st_info >> 4
    }

    pub const fn st_type(&self) -> u8 {
        self.sym.st_info & 0xf
    }

    pub const fn is_global(&self) -> bool {
        self.st_bind() == STB_GLOBAL
    }

    pub const fn is_weak(&self) -> bool {
        self.st_bind() == STB_WEAK
    }

    pub const fn is_tls(&self) -> bool {
        self.st_type() == STT_TLS
    }

    pub const fn is_object(&self) -> bool {
        self.st_type() == STT_OBJECT
    }

    pub const fn is_local(&self) -> bool {
        self.st_bind() == STB_LOCAL
    }

    pub const fn is_undefined(&self) -> bool {
        self.sym.st_shndx == SHN_UNDEF as u16
    }

    pub const fn reference(&self) -> &Path {
        self.reference
    }

    pub const fn got_offset(&self) -> Option<usize> {
        self.in_got
    }

    pub const fn got_plt_offset(&self) -> Option<usize> {
        self.in_got_plt
    }

    pub const fn plt_index(&self) -> Option<usize> {
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

    pub const fn higher_bind_than(&self, sym: Symbol<'_>) -> bool {
        let s1 = self.st_bind();
        let s2 = sym.st_bind();
        !matches!(
            (s1, s2),
            (STB_LOCAL, STB_WEAK) | (STB_LOCAL, STB_GLOBAL) | (STB_WEAK, STB_GLOBAL)
        )
    }

    pub const fn hash(&self) -> u32 {
        self.hash
    }

    pub const fn gnu_hash(&self) -> u32 {
        self.gnu_hash
    }

    pub const fn dynamic(&self) -> Option<SymbolRef> {
        self.dynamic
    }

    pub fn set_dynamic(&mut self, dynamic: SymbolRef) {
        self.dynamic = Some(dynamic);
    }

    pub const fn relocation_offset(&self) -> Option<usize> {
        self.relocation_offset
    }

    pub fn set_relocation_offset(&mut self, offset: usize) {
        self.relocation_offset = Some(offset);
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

impl std::ops::DerefMut for Symbol<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sym
    }
}
