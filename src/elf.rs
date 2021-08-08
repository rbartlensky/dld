use crate::serialize::Serialize;
use goblin::elf64::{header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT}, program_header::{ProgramHeader, PF_R, PF_X, PT_LOAD}, section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS, SHT_NULL, SHT_PROGBITS, SHT_STRTAB, SectionHeader}};
use std::{collections::HashMap, fs::File, io::Write, iter::FromIterator, path::Path};

/// HEADER
/// PH1
/// .text
/// SH1
pub struct Writer<'d> {
    out: File,
    eh: Header,
    names: HashMap<&'static str, usize>,
    string_tab_len: usize,
    program_headers: Vec<ProgramHeader>,
    section_headers: Vec<SectionHeader>,
    sections: HashMap<usize, Vec<&'d [u8]>>,
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
            e_phoff: std::mem::size_of::<Header>() as u64,
            e_shoff: (std::mem::size_of::<Header>() + std::mem::size_of::<ProgramHeader>()) as u64,
            e_flags: 0,
            e_ehsize: std::mem::size_of::<Header>() as u16,
            e_phentsize: std::mem::size_of::<ProgramHeader>() as u16,
            e_phnum: 1,
            e_shentsize: std::mem::size_of::<SectionHeader>() as u16,
            e_shnum: 1,
            e_shstrndx: 0,
        };
        let mut s = Self {
            out,
            eh,
            names: Default::default(),
            string_tab_len: 0,
            program_headers: vec![],
            section_headers: vec![],
            sections: Default::default(),
        };
        s.add_section("", SHT_NULL, 0, 0, 0, 0, None, 0);
        Ok(s)
    }

    fn get_or_create_name(&mut self, name: &'static str) -> (usize, bool) {
        let mut new = false;
        let mut add_len = 0;
        let v = self.string_tab_len;
        let index = self.names.entry(name).or_insert_with(|| {
            add_len = name.len() + 1;
            new = true;
            v
        });
        self.string_tab_len += add_len;
        (*index, new)
    }

    fn add_section(
        &mut self,
        name: &'static str,
        kind: u32,
        flags: u32,
        link: u32,
        info: u32,
        entsize: u64,
        data: Option<&'d [u8]>,
        size: u64,
    ) {
        // let ph = ProgramHeader {
        //     p_type: PT_LOAD,
        //     p_flags: PF_R | PF_X,
        //     p_offset: std::mem::size_of::<Header>() as u64 + std::mem::size_of::<ProgramHeader>() as u64,
        //     p_vaddr: 0x401000,
        //     p_paddr: 0,
        //     p_filesz: text_code.len() as u64,
        //     p_memsz: text_code.len() as u64,
        //     p_align: 0,
        // };

        let (i, new) = self.get_or_create_name(name);
        let size = data.map(|d| d.len() as u64).unwrap_or(size);
        if let Some(data) = data {
            self.sections.entry(i).and_modify(|v| v.push(data)).or_insert_with(|| vec![data]);
        }
        if new {
            let sh = SectionHeader {
                sh_name: i as u32,
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
            let sh = &mut self.section_headers[i];
            sh.sh_size += size;
        }
    }

    pub fn grow_bss(&mut self, size: u64) {
        self.add_section(".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 0, None, size);
    }

    pub fn add_data(&mut self, data: &'d [u8]) {
        self.add_section(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 0, Some(data), 0);
    }

    pub fn add_data1(&mut self, data: &'d [u8]) {
        self.add_section(".data1", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 0, Some(data), 0);
    }

    pub fn add_rodata(&mut self, data: &'d [u8]) {
        self.add_section(".rodata", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 0, Some(data), 0);
    }

    pub fn add_rodata1(&mut self, data: &'d [u8]) {
        self.add_section(".rodata1", SHT_PROGBITS, SHF_ALLOC, 0, 0, 0, Some(data), 0);
    }

    pub fn add_text(&mut self, data: &'d [u8]) {
        self.add_section(".text", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0, 0, 0, Some(data), 0);
    }

    pub fn write_to_disk(mut self) {
        // TODO: remove
        self.eh.e_phoff = 0;
        self.eh.e_phnum = 0;

        let strtab_name = self.get_or_create_name(".strtab").0;

        // + 1 for string table section
        self.eh.e_shnum = self.section_headers.len() as u16 + 1;
        let mut shoff = (std::mem::size_of::<Header>() + self.string_tab_len) as u64;
        for sh in &self.section_headers {
            if let Some(data) = self.sections.get(&(sh.sh_name as usize)) {
                for d in data {
                    shoff += d.len() as u64;
                }
            }
        }
        self.eh.e_shoff = shoff;
        // last section is the string table
        self.eh.e_shstrndx = self.eh.e_shnum - 1;

        // write the header out
        let mut buf = Vec::with_capacity(std::mem::size_of::<Header>());
        self.eh.serialize(&mut buf);
        self.out.write_all(&buf).unwrap();

        // write all data to file
        let mut file_offset = std::mem::size_of::<Header>() as u64;
        for sh in &mut self.section_headers {
            sh.sh_offset = file_offset;
            if let Some(data) = self.sections.remove(&(sh.sh_name as usize)) {
                for d in data {
                    self.out.write_all(&d).unwrap();
                    file_offset += d.len() as u64;
                }
            }
        }

        // write the string table to file
        let mut names = self.names.into_iter().collect::<Vec<(&str, usize)>>();
        names.sort_by(|a, b| a.1.cmp(&b.1));
        for name in names {
            self.out.write_all(name.0.as_bytes()).unwrap();
            self.out.write_all(&[0]).unwrap();
        }

        // add our string table section header
        self.section_headers.push(SectionHeader {
            sh_name: strtab_name as u32,
            sh_type: SHT_STRTAB,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: file_offset,
            sh_size: self.string_tab_len as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });

        // write section headers to disk
        let mut buf = Vec::with_capacity(std::mem::size_of::<SectionHeader>());
        for sh in self.section_headers {
            sh.serialize(&mut buf);
        }
        self.out.write_all(&buf).unwrap();
    }
}
