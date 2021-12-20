use crate::{error::ErrorType, name::Name, serialize::Serialize, symbol::Symbol};
use byteorder::{LittleEndian, WriteBytesExt};
use goblin::elf64::{
    header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT},
    program_header::{ProgramHeader, PF_R, PF_W, PF_X, PT_LOAD},
    reloc::Rela,
    section_header::{
        SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_ABS, SHN_COMMON, SHN_UNDEF,
        SHT_NULL, SHT_PROGBITS, SHT_RELA, SHT_STRTAB, SHT_SYMTAB,
    },
    sym::{Sym, STB_GLOBAL, STB_LOCAL},
};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, HashMap},
    convert::TryInto,
    fs::File,
    io::Write,
    mem::size_of,
    path::Path,
};

mod options;
pub use options::*;

mod string_table;
pub use string_table::StringTable;

const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone, Copy)]
pub struct SectionRef {
    /// The section index where a particular section was relocated to.
    pub index: usize,
    /// The byte offset at which a particular section was relocated to, relative
    /// to the start of the section of `index`.
    pub insertion_point: usize,
}

/// A symbol can be fetched by indexing `symbols` in the following way: `symbols[st_name][index]`.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SymbolRef {
    pub st_name: u32,
    pub index: usize,
}

struct Section {
    /// The section header of the section.
    sh: SectionHeader,
    /// In case we load this section into memory, we will also have an
    /// associated program header.
    ph: Option<ProgramHeader>,
    /// The data of the section.
    data: Vec<u8>,
}

impl Section {
    /// Returns the size of the data, rounded to the next multiple of `PAGE_SIZE`.
    pub fn data_size(&self) -> u64 {
        round_to(self.data.len() as u64, PAGE_SIZE)
    }

    /// Extends the data, such that the length becomes a multiple of `PAGE_SIZE`.
    pub fn align_and_extend_data(&mut self) {
        self.data.extend(std::iter::repeat(0).take(self.data_size() as usize - self.data.len()));
    }
}

impl From<SectionHeader> for Section {
    fn from(sh: SectionHeader) -> Self {
        Self { sh, ph: None, data: vec![] }
    }
}

pub struct Writer<'d> {
    out: File,
    eh: Header,
    section_names: StringTable,
    symbol_names: StringTable,
    symbols: HashMap<u32, Vec<Symbol<'d>>>,
    sections: Vec<Section>,
    got_len: usize,
    plt: HashMap<SymbolRef, usize>,
    got_plt: HashMap<SymbolRef, usize>,
}

impl<'d> Writer<'d> {
    pub fn new(options: &'d options::Options) -> std::io::Result<Self> {
        let out = File::create(options.output.as_path())?;
        let eh = Header {
            #[rustfmt::skip]
            e_ident: [
                ELFMAG[0], ELFMAG[1], ELFMAG[2], ELFMAG[3],
                ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            e_type: ET_EXEC,
            e_machine: EM_X86_64,
            e_version: EV_CURRENT as u32,
            e_entry: 0x401000,
            e_flags: 0,
            e_ehsize: size_of::<Header>() as u16,
            e_phentsize: size_of::<ProgramHeader>() as u16,
            e_phnum: 0,
            e_shentsize: size_of::<SectionHeader>() as u16,
            // we have the the null section initially
            e_shnum: 1,
            // patched in `Writer::write`
            e_phoff: 0,
            e_shoff: 0,
            e_shstrndx: 0,
        };
        let mut s = Self {
            out,
            eh,
            section_names: Default::default(),
            symbol_names: Default::default(),
            symbols: Default::default(),
            sections: Default::default(),
            // first entry reserved
            got_len: 1,
            plt: Default::default(),
            got_plt: Default::default(),
        };
        let null_section = goblin::elf::SectionHeader { sh_type: SHT_NULL, ..Default::default() };
        s.add_section("", &null_section, None);
        let got_section = goblin::elf::SectionHeader {
            sh_type: SHT_PROGBITS,
            sh_flags: (SHF_ALLOC | SHF_WRITE) as u64,
            ..Default::default()
        };
        s.add_section(".got", &got_section, None);
        // .plt's personal .got
        s.add_section(".got.plt", &got_section, None);
        s.add_section(".plt", &got_section, None);
        s.add_symbol(
            Sym { st_shndx: SHN_UNDEF as u16, ..Default::default() },
            None,
            "",
            Path::new(""),
        )
        .unwrap();
        Ok(s)
    }

    // TODO: section merging for mergeable sections:
    // https://docs.oracle.com/cd/E23824_01/html/819-0690/ggdlu.html
    fn add_section(
        &mut self,
        name: impl Into<Name>,
        sh: &goblin::elf::SectionHeader,
        data: Option<Vec<u8>>,
    ) -> SectionRef {
        let entry = self.section_names.get_or_create(name);
        let old_size = if entry.new {
            let sh = SectionHeader {
                sh_name: entry.offset as u32,
                sh_type: sh.sh_type,
                sh_flags: sh.sh_flags as u64,
                sh_size: sh.sh_size,
                sh_link: sh.sh_link,
                sh_info: sh.sh_info,
                sh_entsize: sh.sh_entsize,
                // patched later on
                sh_addr: 0,
                sh_offset: 0,
                sh_addralign: 0,
            };
            let ph = get_program_header(&sh);
            self.sections.push(Section { sh, ph, data: data.unwrap_or_default() });
            0
        } else {
            let section = &mut self.sections[entry.index];
            let old_size = section.data.len();
            section.sh.sh_size += sh.sh_size;
            if let Some(v) = data {
                section.data.extend(v)
            }
            old_size as usize
        };
        SectionRef { index: entry.index, insertion_point: old_size }
    }

    pub fn push_section(
        &mut self,
        name: impl Into<Name>,
        section: &goblin::elf::SectionHeader,
        data: Option<&[u8]>,
    ) -> SectionRef {
        let data = data.map(|v| v.to_owned());
        self.add_section(name, section, data)
    }

    pub fn add_relocation(&mut self, name: impl Into<Name>, r: Rela) {
        let name = name.into();
        let rela_name = format!(".rela{}", &*name);
        let target_section = self.section_names.get(name).unwrap().index;
        let entry = self.section_names.get_or_create(rela_name);
        if entry.new {
            let sh = SectionHeader {
                sh_name: entry.offset as u32,
                sh_type: SHT_RELA,
                sh_size: size_of::<Rela>() as u64,
                // TODO: the section header index of the associated symbol table.
                sh_link: 0,
                sh_info: target_section as u32,
                sh_entsize: size_of::<Rela>() as u64,
                ..Default::default()
            };
            let mut v = vec![0; size_of::<Rela>()];
            r.serialize(&mut v);
            self.sections.push(Section { sh, ph: None, data: v });
        } else {
            let section = &mut self.sections[entry.index];
            section.sh.sh_size += size_of::<Rela>() as u64;
            let mut v = vec![0; size_of::<Rela>()];
            r.serialize(&mut v);
            section.data.extend(v);
        };
    }

    pub fn add_symbol<'s>(
        &mut self,
        mut elf_sym: Sym,
        sec_ref: Option<SectionRef>,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<Option<SymbolRef>, ErrorType> {
        let name = name.to_string();
        let st_name = self.symbol_names.get_or_create(name.clone()).offset as u32;
        elf_sym.st_name = st_name;
        log::trace!("name: '{}' -> sym: {:?}", name, elf_sym);
        if let Some(sec_ref) = sec_ref {
            elf_sym.st_shndx = sec_ref.index as u16;
            elf_sym.st_value += sec_ref.insertion_point as u64;
        } else if ![SHN_ABS, SHN_COMMON, SHN_UNDEF].contains(&(elf_sym.st_shndx as u32)) {
            return Ok(None);
        }
        let sym = Symbol::new(elf_sym, reference);
        let index = match self.symbols.entry(st_name) {
            Entry::Occupied(mut syms) => {
                let mut found = None;
                for (i, s) in syms.get_mut().iter_mut().enumerate() {
                    if s.is_global() {
                        // we already found a definition for this symbol
                        if s.st_shndx as u32 != SHN_UNDEF {
                            return Err(ErrorType::Other(format!(
                                "Symbol {} already defined in {}",
                                name,
                                s.reference().display()
                            )));
                        } else if sym.st_shndx as u32 != SHN_UNDEF {
                            // if we find the same global symbol in another
                            // lib that points to a valid section, we can steal
                            // that symbol to make it defined
                            *s = sym;
                            found = Some(i);
                        } else {
                            // found the same undefined symbol twice, no need to duplicate it
                            found = Some(i);
                        }
                    } else if !s.is_weak() {
                        // if we already have a local symbol with the same name, pointing to
                        // the same section, then there is no need to include it anymore
                        if same_local_symbol(&s.sym, &sym.sym) {
                            found = Some(i);
                        };
                    }
                }
                found.unwrap_or_else(|| {
                    syms.get_mut().push(sym);
                    syms.get_mut().len() - 1
                })
            }
            Entry::Vacant(v) => {
                v.insert(vec![sym]);
                0
            }
        };
        Ok(Some(SymbolRef { st_name, index }))
    }

    pub fn symbol(&self, sym: SymbolRef) -> Symbol<'_> {
        self.symbols[&sym.st_name][sym.index]
    }

    pub fn section_offset(&mut self, section: SectionRef, offset: usize) -> &mut [u8] {
        let offset = offset + section.insertion_point;
        &mut self.sections[section.index].data[offset..offset + size_of::<u64>()]
    }

    pub fn add_got_entry(&mut self, sym: SymbolRef) {
        let sym = &mut self.symbols.get_mut(&sym.st_name).unwrap()[sym.index];
        if sym.got_offset().is_none() {
            sym.set_got_offset(self.got_len * size_of::<u64>());
            // TLS symbols always take up two words in the got:
            //  * module id
            //  * and offset
            self.got_len += if sym.is_tls() { 2 } else { 1 };
        }
    }

    pub fn add_plt_entry(&mut self, sym: SymbolRef) {
        let len = self.plt.len();
        let index = *self.plt.entry(sym).or_insert(len);
        let len = self.got_plt.len() + 3;
        let offset = *self.got_plt.entry(sym).or_insert(len * size_of::<u64>());

        let sym = &mut self.symbols.get_mut(&sym.st_name).unwrap()[sym.index];
        sym.set_got_plt_offset(offset);
        sym.set_plt_index(index);
    }

    pub fn got_address(&self) -> u64 {
        self.sections[1].sh.sh_offset
    }

    pub fn plt_address(&self) -> u64 {
        self.sections[3].sh.sh_offset
    }

    fn compute_got(&mut self) {
        // [1] == .got
        self.sections[1].data.extend(std::iter::repeat(0).take(size_of::<u64>() * (self.got_len)));
        if let Some(e) = self.symbol_names.get("_GLOBAL_OFFSET_TABLE_") {
            let got_addr = self.got_address();
            self.symbols.entry(e.offset as u32).and_modify(|s| {
                // 1 == .got section
                s[0].st_shndx = 1;
                s[0].st_value = got_addr
            });
        }
    }

    fn compute_got_plt(&mut self) {
        // [2] == .got.plt
        self.sections[2].data.reserve(size_of::<u64>() * (self.got_plt.len() + 3));
        self.sections[2]
            .data
            .extend(std::iter::repeat(0).take(size_of::<u64>() * (self.got_plt.len() + 3)));
    }

    fn patch_got_plt(&mut self) {
        let plt_address = self.plt_address();
        // [2] == .got.plt
        for (sym, addr) in &self.got_plt {
            let sym = &self.symbols[&sym.st_name][sym.index];
            // 16 to skip the header, another 16 for all entries before plt_index, and then another 11
            let plt_index = sym.plt_index().unwrap();
            self.sections[2].data[*addr..]
                .as_mut()
                .write_u64::<LittleEndian>(plt_address + 16 * (plt_index as u64 + 1) + 11)
                .unwrap();
        }
    }

    fn compute_plt(&mut self) {
        let got: u32 = self.got_address().try_into().unwrap();
        let mut header = [
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00, // pushq  0x0(%rip)
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x90, 0x90, 0x90, 0x90, // nop nop nop nop
        ];
        header[2..].as_mut().write_u32::<LittleEndian>(got + 8).unwrap();
        header[8..].as_mut().write_u32::<LittleEndian>(got + 16).unwrap();
        // [3] == .plt
        self.sections[3].data.reserve((self.plt.len() + 1) * 16);
        self.sections[3].data.extend(header);

        let entry = [
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x68, 0x00, 0x00, 0x00, 0x00, // push   $0x00000000
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmpq   0x0
        ];
        for _ in 0..self.plt.len() {
            self.sections[3].data.extend(&entry);
        }
        for (symbol_ref, plt_index) in &self.plt {
            let entry = &mut self.sections[3].data[16 * (plt_index + 1)..];
            let sym = &self.symbols[&symbol_ref.st_name][symbol_ref.index];
            let got_plt_offset = sym.got_plt_offset().unwrap().try_into().unwrap();
            let plt_index: u32 = (*plt_index).try_into().unwrap();
            entry[2..].as_mut().write_u32::<LittleEndian>(got_plt_offset).unwrap();
            entry[7..].as_mut().write_u32::<LittleEndian>(plt_index).unwrap();
            // we need to jump over all of the entries that we wrote so far, and the header
            let plt_start_offset = (plt_index + 2) * 16;
            entry[12..].as_mut().write_u32::<LittleEndian>(plt_start_offset).unwrap();
        }
    }

    // elf header
    // section 1
    // section 2
    // section header 1
    // section header 2
    // program header 1
    // ...
    pub fn compute_sections(&mut self) -> Result<(), ErrorType> {
        let symtab_name = self.section_names.get_or_create(".symtab").offset;
        let strtab_name = self.section_names.get_or_create(".strtab").offset;
        let shstrtab_name = self.section_names.get_or_create(".shstrtab").offset;

        self.compute_got();
        self.compute_got_plt();
        self.compute_plt();

        // + 3 for strings and symbol table section
        self.eh.e_shnum = self.sections.len() as u16 + 3;
        let mut shoff = (size_of::<Header>()
            + self.section_names.total_len()
            + self.symbol_names.total_len()
            + self.symbols.values().flatten().count() * size_of::<Sym>())
            as u64;
        for section in &mut self.sections {
            shoff += section.data_size();
            self.eh.e_phnum += section.ph.map(|_| 1).unwrap_or_default();
        }
        self.eh.e_shoff = shoff;
        // the program header comes right after all the sections + headers
        self.eh.e_phoff = shoff + (self.eh.e_shnum as usize * size_of::<SectionHeader>()) as u64;
        // last section is the section header string table
        self.eh.e_shstrndx = self.eh.e_shnum - 1;

        let mut p_vaddr = self.eh.e_entry;
        // write all section data to file, and patch section and program headers
        let mut file_offset = size_of::<Header>() as u64;
        for section in &mut self.sections {
            section.sh.sh_offset = file_offset;
            if let Some(ph) = &mut section.ph {
                section.sh.sh_addr = p_vaddr;
                section.sh.sh_addralign = PAGE_SIZE;
                ph.p_offset = file_offset;
                ph.p_vaddr = p_vaddr;
                ph.p_paddr = p_vaddr;
                ph.p_filesz = section.sh.sh_size;
                ph.p_memsz = section.sh.sh_size;
                p_vaddr += round_to(section.sh.sh_size, PAGE_SIZE);
            }
            if !section.data.is_empty() {
                section.align_and_extend_data();
                file_offset += section.data.len() as u64;
            }
        }

        // write the symbols to disk and make sure that locals come first
        let mut section = vec![];
        let mut section_len = 0;
        let mut syms: Vec<&mut Sym> =
            self.symbols.values_mut().flatten().map(|s| &mut s.sym).collect();
        syms.sort_by(|s1, s2| sort_symbols_func(s1, s2));
        let mut undefined_symbols = vec![];
        let mut last_local = 0;
        for sym in syms {
            let st_bind = sym.st_info >> 4;
            if sym.st_shndx as u32 == SHN_UNDEF && st_bind == STB_GLOBAL {
                undefined_symbols
                    .push(self.symbol_names.name(sym.st_name as usize).unwrap().to_string());
                continue;
            }
            // since we now have an address for our sections, we can patch the
            // final value of all symbols
            sym.st_value +=
                self.sections.get(sym.st_shndx as usize).map(|s| s.sh.sh_addr).unwrap_or(0);
            section_len += sym.serialize(&mut section);
            if st_bind == STB_LOCAL {
                last_local += 1;
            }
        }
        if !undefined_symbols.is_empty() {
            return Err(ErrorType::Other(format!(
                "undefined symbols: {}",
                format_list(&undefined_symbols)
            )));
        }

        // add our symbol table section header
        self.sections.push(Section {
            sh: SectionHeader {
                sh_name: symtab_name as u32,
                sh_type: SHT_SYMTAB,
                sh_offset: file_offset,
                sh_size: section_len as u64,
                sh_link: self.sections.len() as u32 + 1,
                sh_info: last_local,
                sh_entsize: size_of::<Sym>() as u64,
                ..Default::default()
            },
            ph: None,
            data: section,
        });
        file_offset += section_len as u64;

        let mut section = vec![];
        let names = self.symbol_names.sorted_names();
        for (name, _) in names {
            name.serialize(&mut section);
        }

        // add our symbol string table section header
        self.sections.push(Section {
            sh: SectionHeader {
                sh_name: strtab_name as u32,
                sh_type: SHT_STRTAB,
                sh_offset: file_offset,
                sh_size: self.symbol_names.total_len() as u64,
                ..Default::default()
            },
            ph: None,
            data: section,
        });
        file_offset += self.symbol_names.total_len() as u64;

        // write the string table to file
        let mut section = vec![];
        let names = self.section_names.sorted_names();
        for (name, _) in names {
            name.serialize(&mut section);
        }

        // add our string table section header
        self.sections.push(Section {
            sh: SectionHeader {
                sh_name: shstrtab_name as u32,
                sh_type: SHT_STRTAB,
                sh_offset: file_offset,
                sh_size: self.section_names.total_len() as u64,
                ..Default::default()
            },
            ph: None,
            data: section,
        });

        self.patch_got_plt();
        Ok(())
    }

    pub fn write_to_disk(mut self) {
        self.eh.serialize(&mut self.out);
        for section in &self.sections {
            self.out.write_all(&section.data).unwrap();
        }
        for section in &self.sections {
            section.sh.serialize(&mut self.out);
        }
        for section in self.sections {
            if let Some(ph) = section.ph {
                ph.serialize(&mut self.out);
            }
        }
    }
}

fn st_type(st_info: u8) -> u8 {
    st_info & 0xf
}

fn st_bind(st_info: u8) -> u8 {
    st_info >> 4
}

// local before global, notype before other types
fn sort_symbols_func(s1: &Sym, s2: &Sym) -> Ordering {
    let b1 = st_bind(s1.st_info);
    let b2 = st_bind(s2.st_info);
    let t1 = st_type(s1.st_info);
    let t2 = st_type(s2.st_info);
    match b1.cmp(&b2) {
        Ordering::Equal => t1.cmp(&t2),
        c => c,
    }
}

const fn round_to(val: u64, multiple: u64) -> u64 {
    let rem = val % multiple;
    val + if rem != 0 { multiple - rem } else { 0 }
}

fn get_program_header(sh: &SectionHeader) -> Option<ProgramHeader> {
    if sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
        let write = if sh.sh_flags as u32 & SHF_WRITE == SHF_WRITE { PF_W } else { 0 };
        let exec = if sh.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR { PF_X } else { 0 };
        Some(ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | write | exec,
            p_align: PAGE_SIZE,
            // all of these are patched later
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
        })
    } else {
        None
    }
}

pub(crate) fn same_local_symbol(s1: &Sym, s2: &Sym) -> bool {
    s1.st_name == s2.st_name
        && s1.st_info == s2.st_info
        && s1.st_other == s2.st_other
        && s1.st_shndx == s2.st_shndx
        && s1.st_size == s2.st_size
}

fn format_list(v: &[String]) -> String {
    let mut s = String::from("[");
    s += &v.join(", ");
    s += "]";
    s
}
