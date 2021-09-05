use crate::{error::ErrorType, serialize::Serialize, symbol::Symbol};
use goblin::elf64::{
    header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT},
    program_header::{ProgramHeader, PF_R, PF_X, PT_LOAD},
    section_header::{
        SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_NULL, SHT_PROGBITS,
        SHT_STRTAB, SHT_SYMTAB,
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
    program_headers: Vec<ProgramHeader>,
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
            e_phoff: size_of::<Header>() as u64,
            e_shoff: (size_of::<Header>() + size_of::<ProgramHeader>()) as u64,
            e_flags: 0,
            e_ehsize: size_of::<Header>() as u16,
            e_phentsize: size_of::<ProgramHeader>() as u16,
            e_phnum: 1,
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
            program_headers: vec![],
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
    ) {
        // let ph = ProgramHeader {
        //     p_type: PT_LOAD,
        //     p_flags: PF_R | PF_X,
        //     p_offset: size_of::<Header>() as u64 + size_of::<ProgramHeader>() as u64,
        //     p_vaddr: 0x401000,
        //     p_paddr: 0,
        //     p_filesz: text_code.len() as u64,
        //     p_memsz: text_code.len() as u64,
        //     p_align: 0,
        // };

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
    }

    pub fn push_section(
        &mut self,
        name: String,
        section: &goblin::elf::SectionHeader,
        data: Option<&[u8]>,
    ) {
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
        );
    }

    pub fn add_symbol<'s>(
        &mut self,
        mut elf_sym: Sym,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<(), ErrorType> {
        let name = name.to_string();
        elf_sym.st_name = self.symbol_names.get_or_create(name.clone()).offset as u32;
        let sym = Symbol::new(name, &elf_sym, reference);
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

    pub fn write_to_disk(mut self) {
        // TODO: remove
        self.eh.e_phoff = 0;
        self.eh.e_phnum = 0;

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
            if let Some(data) = self.sections.get(&(sh.sh_name as usize)) {
                shoff += data.len() as u64;
            }
        }
        self.eh.e_shoff = shoff;
        // last section is the string table
        self.eh.e_shstrndx = self.eh.e_shnum - 1;

        // write the header out
        let mut buf = Vec::with_capacity(size_of::<Header>());
        self.eh.serialize(&mut buf);
        self.out.write_all(&buf).unwrap();

        // write all data to file
        let mut file_offset = size_of::<Header>() as u64;
        for sh in &mut self.section_headers {
            sh.sh_offset = file_offset;
            if let Some(data) = self.sections.remove(&(sh.sh_name as usize)) {
                self.out.write_all(&data).unwrap();
                file_offset += data.len() as u64;
            }
        }

        buf = Vec::with_capacity(size_of::<Sym>());
        // write the symbols
        let mut syms: Vec<&Sym> = self.symbols.values().flatten().collect();
        syms.sort_by(|s1, s2| (s1.st_info >> 4).cmp(&(s2.st_info >> 4)));
        let mut last_local = 0;
        for sym in syms {
            sym.serialize(&mut buf);
            let st_bind = sym.st_info >> 4;
            if st_bind == STB_LOCAL {
                last_local += 1;
            }
        }
        self.out.write_all(&buf).unwrap();

        // add our symbol table section header
        self.section_headers.push(SectionHeader {
            sh_name: symtab_name as u32,
            sh_type: SHT_SYMTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: file_offset,
            sh_size: buf.len() as u64,
            sh_link: self.section_headers.len() as u32 + 1,
            sh_info: last_local,
            sh_addralign: 0,
            sh_entsize: size_of::<Sym>() as u64,
        });
        file_offset += buf.len() as u64;

        // write the symbol names to file
        let names = self.symbol_names.sorted_names();
        for name in names {
            self.out.write_all(name.0.as_bytes()).unwrap();
            self.out.write_all(&[0]).unwrap();
        }
        file_offset += self.symbol_names.total_len() as u64;

        // add our string table section header
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
        buf = Vec::with_capacity(size_of::<SectionHeader>());
        for sh in self.section_headers {
            sh.serialize(&mut buf);
        }
        self.out.write_all(&buf).unwrap();
    }
}
