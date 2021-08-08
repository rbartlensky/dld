use crate::symbol::Symbol;
use goblin::elf::{
    section_header::{SHT_NOBITS, SHT_PROGBITS},
    sym::{STB_GLOBAL, STB_WEAK, STT_NOTYPE},
    Elf,
};

fn get_name<'e>(elf: &'e Elf<'e>, index: usize) -> Result<&'e str, String> {
    elf.strtab.get_at(index).ok_or_else(|| "Symbol not found in strtab.".to_string())
}

pub struct Object<'e> {
    elf: Elf<'e>,
    buf: &'e [u8],
    text_section: usize,
    data_section: usize,
    bss_section: usize,
}

impl<'e> Object<'e> {
    pub fn new(elf: Elf<'e>, buf: &'e [u8]) -> Self {
        let (mut text_section, mut data_section, mut bss_section) = (0, 0, 0);
        for (i, sh) in elf.section_headers.iter().enumerate() {
            if sh.sh_type == SHT_PROGBITS && sh.is_alloc() && sh.is_executable() {
                text_section = i;
            } else if sh.sh_type == SHT_PROGBITS && sh.is_alloc() && sh.is_writable() {
                data_section = i;
            } else if sh.sh_type == SHT_NOBITS && sh.is_alloc() && sh.is_writable() {
                bss_section = i;
            }
        }
        Self { elf, buf, text_section, data_section, bss_section }
    }

    pub fn global_symbols(&self) -> Result<Vec<(String, Symbol)>, crate::ErrorType> {
        self.elf
            .syms
            .iter()
            .filter(|sym| {
                let bind = sym.st_bind();
                (bind == STB_WEAK || bind == STB_GLOBAL) && sym.st_type() != STT_NOTYPE
            })
            .map(|sym| {
                let name = get_name(&self.elf, sym.st_name)?;
                Ok((name.into(), Symbol::new(sym.st_bind() == STB_WEAK)))
            })
            .collect()
    }

    pub fn text_section(&self) -> &[u8] {
        let section = &self.elf.section_headers[self.text_section];
        // progbits always have a range
        let range = section.file_range().unwrap();
        &self.buf[range]
    }

    pub fn data_section(&self) -> &[u8] {
        let section = &self.elf.section_headers[self.data_section];
        // progbits always have a range
        let range = section.file_range().unwrap();
        &self.buf[range]
    }
}
