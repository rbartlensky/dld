use crate::{error::ErrorType, serialize::Serialize, symbol::Symbol};
use goblin::elf64::{
    header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT},
    program_header::{ProgramHeader, PF_R, PF_W, PF_X, PT_LOAD},
    section_header::{
        SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NULL, SHT_STRTAB, SHT_SYMTAB,
    },
    sym::{Sym, STB_LOCAL},
};
use std::{
    collections::{hash_map::Entry, HashMap},
    fs::File,
    io::Write,
    mem::size_of,
    path::Path,
};

use crate::name::Name;

mod string_table;
use string_table::StringTable;

pub struct Writer<'d> {
    out: File,
    eh: Header,
    section_names: StringTable,
    symbol_names: StringTable,
    symbols: HashMap<Symbol<'d>, Vec<Sym>>,
    section_headers: Vec<SectionHeader>,
    sections: HashMap<usize, Vec<u8>>,
}

impl<'d> Writer<'d> {
    pub fn new(output: &Path) -> std::io::Result<Self> {
        let out = File::create(output)?;
        let eh = Header {
            e_ident: [
                ELFMAG[0],
                ELFMAG[1],
                ELFMAG[2],
                ELFMAG[3],
                ELFCLASS64,
                ELFDATA2LSB,
                EV_CURRENT,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            e_type: ET_EXEC,
            e_machine: EM_X86_64,
            e_version: EV_CURRENT as u32,
            e_entry: 0x401000,
            e_phoff: 0,
            e_shoff: (size_of::<Header>() + size_of::<ProgramHeader>()) as u64,
            e_flags: 0,
            e_ehsize: size_of::<Header>() as u16,
            e_phentsize: size_of::<ProgramHeader>() as u16,
            e_phnum: 0,
            e_shentsize: size_of::<SectionHeader>() as u16,
            e_shnum: 1,
            e_shstrndx: 0,
        };
        let mut s = Self {
            out,
            eh,
            section_names: Default::default(),
            symbol_names: Default::default(),
            symbols: Default::default(),
            section_headers: vec![],
            sections: Default::default(),
        };
        s.add_section("", SHT_NULL, 0, 0, 0, 0, None, 0);
        Ok(s)
    }

    fn add_section(
        &mut self,
        name: impl Into<Name>,
        kind: u32,
        flags: u32,
        link: u32,
        info: u32,
        entsize: u64,
        data: Option<Vec<u8>>,
        size: u64,
    ) -> usize {
        let entry = self.section_names.get_or_create(name);
        let size = data.as_ref().map(|d| d.len() as u64).unwrap_or(size);
        if let Some(data) = data {
            self.sections.entry(entry.index).and_modify(|v| v.extend(&data)).or_insert(data);
        }
        if entry.new {
            let sh = SectionHeader {
                sh_name: entry.offset as u32,
                sh_type: kind,
                sh_flags: flags as u64,
                // patched later on
                sh_addr: 0,
                // patched later on
                sh_offset: 0,
                sh_size: size,
                sh_link: link,
                sh_info: info,
                sh_addralign: 0,
                sh_entsize: entsize,
            };
            self.section_headers.push(sh);
        } else {
            let sh = &mut self.section_headers[entry.index];
            sh.sh_size += size;
        }
        entry.index
    }

    pub fn push_section(
        &mut self,
        name: String,
        section: &goblin::elf::SectionHeader,
        data: Option<&[u8]>,
    ) -> usize {
        let data = data.map(|v| v.to_owned());
        self.add_section(
            name,
            section.sh_type,
            section.sh_flags as u32,
            section.sh_link,
            section.sh_info,
            section.sh_entsize,
            data,
            section.sh_size,
        )
    }

    pub fn add_symbol<'s>(
        &mut self,
        mut elf_sym: Sym,
        new_shndx: usize,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<(), ErrorType> {
        let name = name.to_string();
        elf_sym.st_name = self.symbol_names.get_or_create(name.clone()).offset as u32;
        let sym = Symbol::new(name, &elf_sym, reference);
        elf_sym.st_shndx = new_shndx as u16;
        match self.symbols.entry(sym) {
            Entry::Occupied(mut s) => {
                if s.key().is_global() {
                    Err(ErrorType::Other(format!(
                        "Symbol {} already defined in {}",
                        s.key().name(),
                        s.key().reference().display()
                    )))
                } else if !s.key().is_weak() {
                    s.get_mut().push(elf_sym);
                    Ok(())
                } else {
                    Ok(())
                }
            }
            Entry::Vacant(v) => {
                v.insert(vec![elf_sym]);
                Ok(())
            }
        }
    }

    pub fn patch_section(&mut self, section: usize, offset: usize, value: u64) {
        use byteorder::{LittleEndian, WriteBytesExt};

        let mut slice = &mut self.sections.get_mut(&section).unwrap()[offset..offset + 8];
        slice.write_u64::<LittleEndian>(value).unwrap();
    }

    // elf header
    // section 1
    // section 2
    // section header 1
    // section header 2
    // program header 1
    // ...
    pub fn write_to_disk(mut self) {
        let symtab_name = self.section_names.get_or_create(".symtab").offset;
        let strtab_name = self.section_names.get_or_create(".strtab").offset;
        let shstrtab_name = self.section_names.get_or_create(".shstrtab").offset;

        // + 3 for strings and symbol table section
        self.eh.e_shnum = self.section_headers.len() as u16 + 3;
        let mut shoff = (size_of::<Header>()
            + self.section_names.total_len()
            + self.symbol_names.total_len()
            + self.symbols.values().flatten().count() * size_of::<Sym>())
            as u64;
        for sh in &self.section_headers {
            let data_len =
                self.sections.get(&(sh.sh_name as usize)).map(|v| v.len()).unwrap_or_default()
                    as u64;
            if sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
                self.eh.e_phnum += 1;
            }
            shoff += data_len;
        }
        self.eh.e_shoff = shoff;
        // the program header comes right after all the sections in our case
        self.eh.e_phoff = shoff + (self.eh.e_shnum as usize * (size_of::<SectionHeader>() - 4)) as u64;
        // last section is the string table
        self.eh.e_shstrndx = self.eh.e_shnum - 1;

        // write the header out
        self.eh.serialize(&mut self.out);

        let mut program_headers = vec![];
        let mut p_vaddr = 0x401000;

        // write all data to file
        let mut file_offset = size_of::<Header>() as u64;
        for sh in &mut self.section_headers {
            sh.sh_offset = file_offset;
            let data = self.sections.remove(&(sh.sh_name as usize)).unwrap_or_default();
            if sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
                let write = if sh.sh_flags as u32 & SHF_WRITE == SHF_WRITE { PF_W } else { 0 };
                let exec =
                    if sh.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR { PF_X } else { 0 };
                program_headers.push(ProgramHeader {
                    p_type: PT_LOAD,
                    p_flags: PF_R | write | exec,
                    p_offset: file_offset,
                    p_vaddr,
                    p_paddr: 0,
                    p_filesz: data.len() as u64,
                    p_memsz: sh.sh_size,
                    p_align: 0,
                });
                p_vaddr += sh.sh_size;
            }
            if !data.is_empty() {
                self.out.write_all(&data).unwrap();
                file_offset += data.len() as u64;
            }
        }

        // write the symbols
        let mut section_len = 0;
        let mut syms: Vec<&Sym> = self.symbols.values().flatten().collect();
        syms.sort_by(|s1, s2| (s1.st_info >> 4).cmp(&(s2.st_info >> 4)));
        let mut last_local = 0;
        for sym in syms {
            section_len += sym.serialize(&mut self.out);
            let st_bind = sym.st_info >> 4;
            if st_bind == STB_LOCAL {
                last_local += 1;
            }
        }

        // add our symbol table section header
        self.section_headers.push(SectionHeader {
            sh_name: symtab_name as u32,
            sh_type: SHT_SYMTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: file_offset,
            sh_size: section_len as u64,
            sh_link: self.section_headers.len() as u32 + 1,
            sh_info: last_local,
            sh_addralign: 0,
            sh_entsize: size_of::<Sym>() as u64,
        });
        file_offset += section_len as u64;

        // write the symbol names to file
        let names = self.symbol_names.sorted_names();
        for name in names {
            self.out.write_all(name.0.as_bytes()).unwrap();
            self.out.write_all(&[0]).unwrap();
        }

        // add our symbol string table section header
        self.section_headers.push(SectionHeader {
            sh_name: strtab_name as u32,
            sh_type: SHT_STRTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: file_offset,
            sh_size: self.symbol_names.total_len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
        file_offset += self.symbol_names.total_len() as u64;

        // write the string table to file
        let names = self.section_names.sorted_names();
        for name in names {
            self.out.write_all(name.0.as_bytes()).unwrap();
            self.out.write_all(&[0]).unwrap();
        }

        // add our string table section header
        self.section_headers.push(SectionHeader {
            sh_name: shstrtab_name as u32,
            sh_type: SHT_STRTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: file_offset,
            sh_size: self.section_names.total_len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });

        // write section headers to disk
        for sh in self.section_headers {
            sh.serialize(&mut self.out);
        }

        // write program headers to disk
        for ph in program_headers {
            ph.serialize(&mut self.out);
        }
    }
}
