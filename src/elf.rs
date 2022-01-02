use crate::{error::ErrorType, name::Name, serialize::Serialize, symbol::Symbol};
use byteorder::{LittleEndian, WriteBytesExt};
use goblin::elf64::{
    header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT},
    program_header::{ProgramHeader, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD},
    reloc::{Rela, R_X86_64_TLSGD},
    section_header::{
        SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_UNDEF, SHT_DYNAMIC, SHT_DYNSYM,
        SHT_FINI_ARRAY, SHT_GNU_HASH, SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS, SHT_NULL, SHT_PROGBITS,
        SHT_RELA, SHT_STRTAB, SHT_SYMTAB,
    },
    sym::{Sym, STB_GLOBAL, STB_LOCAL},
};
use std::{collections::HashMap, convert::TryInto, fs::File, io::Write, mem::size_of, path::Path};

mod options;
pub use options::*;

mod string_table;
pub use string_table::StringTable;

mod symbol_table;
pub use symbol_table::{GnuHashTable, HashTable, SymbolRef, SymbolTable};

#[derive(Debug, Clone, Copy)]
pub struct SectionRef {
    /// The section index where a particular section was relocated to.
    pub index: usize,
    /// The byte offset at which a particular section was relocated to, relative
    /// to the start of the section of `index`.
    pub insertion_point: usize,
}

pub struct Section {
    /// The section header of the section.
    sh: SectionHeader,
    /// The data of the section.
    data: Vec<u8>,
}

impl From<SectionHeader> for Section {
    fn from(sh: SectionHeader) -> Self {
        Self { sh, data: vec![] }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DynTag {
    /// Marks end of dynamic section
    Null = 0,
    /// Name of needed library
    Needed = 1,
    /// Size in bytes of PLT relocs
    Pltrelsz = 2,
    /// Processor defined value
    Pltgot = 3,
    /// Address of symbol hash table
    Hash = 4,
    /// Address of string table
    StrTab = 5,
    /// Address of symbol table
    SymTab = 6,
    /// Address of Rela relocs
    Rela = 7,
    /// Total size of Rela relocs
    RelaSize = 8,
    /// Size of one Rela reloc
    RelaEnt = 9,
    /// Size of string table
    StrSize = 10,
    /// Size of one symbol table entry
    SymEnt = 11,
    /// Address of init function
    Init = 12,
    /// Address of termination function
    Fini = 13,
    /// Name of shared object
    Soname = 14,
    /// Library search path (deprecated)
    Rpath = 15,
    /// Start symbol search here
    Symbolic = 16,
    /// Address of Rel relocs
    Rel = 17,
    /// Total size of Rel relocs
    Relsz = 18,
    /// Size of one Rel reloc
    Relent = 19,
    /// Type of reloc in PLT
    Pltrel = 20,
    /// For debugging, unspecified
    Debug = 21,
    /// Reloc might modify .text
    Textrel = 22,
    /// Address of PLT relocs
    Jmprel = 23,
    /// Process relocations of object
    BindNow = 24,
    /// Array with addresses of init fct
    InitArray = 25,
    /// Array with addresses of fini fct
    FiniArray = 26,
    /// Size in bytes of DT_INIT_ARRAY
    InitArraySize = 27,
    /// Size in bytes of DT_FINI_ARRAY
    FiniArraySize = 28,
    /// Library search path
    Runpath = 29,
    /// GNU-style hash table
    GnuHash = 0x6fff_fef5,
    /// Indicates that all Elf32_Rela (or Elf64_Rela) RELATIVE relocations have been
    /// concatenated together, and specifies the RELATIVE relocation count
    RelaCount = 0x6fff_fff9,
}

pub struct Writer<'d> {
    out: File,
    hash_style: options::HashStyle,
    eh: Header,
    section_names: StringTable,
    symbol_names: StringTable,
    symbols: SymbolTable<'d>,
    dyn_symbol_names: StringTable,
    dyn_symbols: SymbolTable<'d>,
    // a mapping from a symbol with name "foo" to a dynamic symbol with the same name
    symbol_mapping: HashMap<SymbolRef, SymbolRef>,
    dyn_rels: Vec<(Rela, SymbolRef)>,
    sections: Vec<Section>,
    got_len: usize,
    plt: HashMap<SymbolRef, usize>,
    got_plt: HashMap<SymbolRef, usize>,
    dyn_entries: Vec<(DynTag, u64)>,
    program_headers: Vec<ProgramHeader>,
    p_vaddr: u64,
    file_offset: u64,
    got_section: usize,
    plt_section: usize,
    got_plt_section: usize,
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
            e_flags: 0,
            e_ehsize: size_of::<Header>() as u16,
            e_phentsize: size_of::<ProgramHeader>() as u16,
            e_shentsize: size_of::<SectionHeader>() as u16,
            // patched in `Writer::write`
            e_entry: 0,
            e_phnum: 0,
            e_shnum: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_shstrndx: 0,
        };
        let mut s = Self {
            out,
            hash_style: options.hash_style,
            eh,
            section_names: Default::default(),
            symbol_names: Default::default(),
            symbols: Default::default(),
            dyn_symbol_names: Default::default(),
            dyn_symbols: Default::default(),
            dyn_rels: vec![],
            symbol_mapping: Default::default(),
            sections: Default::default(),
            // first entry reserved
            got_len: 1,
            plt: Default::default(),
            got_plt: Default::default(),
            dyn_entries: vec![],
            program_headers: vec![],
            p_vaddr: 0x40000,
            file_offset: size_of::<Header>() as u64,
            got_section: 0,
            plt_section: 0,
            got_plt_section: 0,
        };

        let null_section = goblin::elf::SectionHeader { sh_type: SHT_NULL, ..Default::default() };
        s.add_section("", &null_section, None);

        let loader = options
            .dynamic_linker
            .to_str()
            .unwrap()
            .as_bytes()
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect::<Vec<u8>>();
        let interp_section = goblin::elf::SectionHeader {
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC as u64,
            sh_size: loader.len() as u64,
            sh_addralign: 1,
            ..Default::default()
        };
        s.add_section(".interp", &interp_section, Some(loader));
        s.add_needed(options.dynamic_linker.file_name().unwrap().to_str().unwrap());

        let got_section = goblin::elf::SectionHeader {
            sh_type: SHT_PROGBITS,
            sh_flags: (SHF_ALLOC | SHF_WRITE) as u64,
            sh_addralign: size_of::<u64>() as u64,
            ..Default::default()
        };
        s.got_section = s.add_section(".got", &got_section, None).index;
        // .plt's personal .got
        s.got_plt_section = s.add_section(".got.plt", &got_section, None).index;
        s.plt_section = s.add_section(".plt", &got_section, None).index;

        let null_sym = Sym { st_shndx: SHN_UNDEF as u16, ..Default::default() };
        s.add_symbol(null_sym, None, "", Path::new("")).unwrap();
        s.add_dyn_symbol(null_sym, None, "", Path::new("")).unwrap();
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
                sh_addralign: sh.sh_addralign,
                // patched later on
                sh_addr: 0,
                sh_offset: 0,
            };
            self.sections.push(Section { sh, data: data.unwrap_or_default() });
            0
        } else {
            let section = &mut self.sections[entry.index];
            let old_size = section.data.len();
            section.sh.sh_size += sh.sh_size;
            section.sh.sh_addralign = std::cmp::max(section.sh.sh_addralign, sh.sh_addralign);
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

    pub fn add_dyn_relocation(&mut self, r: Rela, sym: SymbolRef) {
        self.dyn_rels.push((r, sym));
    }

    fn add_symbol_inner<'s>(
        mut elf_sym: Sym,
        sec_ref: Option<SectionRef>,
        name: &'s str,
        reference: &'d Path,
        symbol_names: &mut StringTable,
        symbols: &mut SymbolTable<'d>,
    ) -> Result<Option<SymbolRef>, ErrorType> {
        let name: Name = name.to_string().into();
        let hash = name.elf_hash();
        let gnu_hash = name.elf_gnu_hash();
        let st_name = symbol_names.get_or_create(name.clone()).offset as u32;
        elf_sym.st_name = st_name;
        log::trace!("name: '{}' -> sym: {:?}", &name as &str, elf_sym);
        if let Some(sec_ref) = sec_ref {
            elf_sym.st_shndx = sec_ref.index as u16;
            elf_sym.st_value += sec_ref.insertion_point as u64;
        }
        symbols
            .add_symbol(elf_sym, hash, gnu_hash, reference)
            .map_err(|e| ErrorType::Other(format!("{} {}", &name as &str, e)))
    }

    pub fn add_symbol<'s>(
        &mut self,
        elf_sym: Sym,
        sec_ref: Option<SectionRef>,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<Option<SymbolRef>, ErrorType> {
        Self::add_symbol_inner(
            elf_sym,
            sec_ref,
            name,
            reference,
            &mut self.symbol_names,
            &mut self.symbols,
        )
    }

    pub fn add_dyn_symbol<'s>(
        &mut self,
        mut elf_sym: Sym,
        sec_ref: Option<SectionRef>,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<Option<SymbolRef>, ErrorType> {
        elf_sym.st_shndx = SHN_UNDEF as u16;
        elf_sym.st_size = 0;
        elf_sym.st_value = 0;
        let r = Self::add_symbol_inner(
            elf_sym,
            sec_ref,
            name,
            reference,
            &mut self.dyn_symbol_names,
            &mut self.dyn_symbols,
        );
        if let Ok(Some(s)) = r {
            if let Some(entry) = self.symbol_names.get(name.to_string()) {
                self.symbol_mapping.insert(SymbolRef { st_name: entry.offset as u32 }, s);
            }
        }
        r
    }

    pub fn symbol(&self, sym: SymbolRef) -> Symbol<'_> {
        *self.symbols.get(sym).unwrap()
    }

    pub fn symbol_name(&self, sym: SymbolRef) -> &str {
        self.symbol_names.name(sym.st_name as usize).unwrap()
    }

    pub fn undefined_symbols(&self) -> Vec<SymbolRef> {
        let mut undefined = vec![];
        for (st_name, sym) in self.symbols.iter() {
            if sym.st_shndx as u32 == SHN_UNDEF && sym.st_bind() == STB_GLOBAL {
                undefined.push(SymbolRef { st_name: *st_name });
            }
        }
        undefined
    }

    pub fn section_offset(&mut self, section: SectionRef, offset: usize) -> &mut [u8] {
        let offset = offset + section.insertion_point;
        &mut self.sections[section.index].data[offset..offset + size_of::<u64>()]
    }

    pub fn add_got_entry(&mut self, sym: SymbolRef, r_type: u32) {
        let sym = self.symbols.get_mut(sym).unwrap();
        if sym.got_offset().is_none() {
            sym.set_got_offset(self.got_len * size_of::<u64>());
            // For TLSGD relocations we need to allocate two slots
            self.got_len += if sym.is_tls() && r_type == R_X86_64_TLSGD { 2 } else { 1 };
        }
    }

    pub fn add_plt_entry(&mut self, sym: SymbolRef) {
        let len = self.plt.len();
        let index = *self.plt.entry(sym).or_insert(len);
        let len = self.got_plt.len() + 3;
        let offset = *self.got_plt.entry(sym).or_insert(len * size_of::<u64>());

        let sym = self.symbols.get_mut(sym).unwrap();
        sym.set_got_plt_offset(offset);
        sym.set_plt_index(index);
    }

    pub fn got_address(&self) -> u64 {
        self.sections[self.got_section].sh.sh_addr
    }

    pub fn plt_address(&self) -> u64 {
        self.sections[self.plt_section].sh.sh_addr
    }

    pub fn add_needed(&mut self, so_name: &str) {
        let entry = self.dyn_symbol_names.get_or_create(so_name.to_string());
        if entry.new {
            self.dyn_entries.push((DynTag::Needed, entry.offset as u64));
        }
    }

    fn compute_got(&mut self) {
        self.sections[self.got_section]
            .data
            .extend(std::iter::repeat(0).take(size_of::<u64>() * (self.got_len)));
        if let Some(e) = self.symbol_names.get("_GLOBAL_OFFSET_TABLE_") {
            let got_addr = self.got_address();
            if let Some(s) = self.symbols.get_mut(SymbolRef { st_name: e.offset as u32 }) {
                s.st_shndx = self.got_section as u16;
                s.st_value = got_addr
            };
        }
        self.sections[self.got_section].sh.sh_size =
            self.sections[self.got_section].data.len() as u64;
    }

    fn compute_got_plt(&mut self) {
        self.sections[self.got_plt_section]
            .data
            .reserve(size_of::<u64>() * (self.got_plt.len() + 3));
        self.sections[self.got_plt_section]
            .data
            .extend(std::iter::repeat(0).take(size_of::<u64>() * (self.got_plt.len() + 3)));
        self.sections[self.got_plt_section].sh.sh_size =
            self.sections[self.got_plt_section].data.len() as u64;
    }

    fn patch_got_plt(&mut self) {
        let plt_address = self.plt_address();
        for (sym, addr) in &self.got_plt {
            let sym = self.symbols.get(*sym).unwrap();
            // 16 to skip the header, another 16 for all entries before plt_index, and then another 11
            let plt_index = sym.plt_index().unwrap();
            self.sections[self.got_plt_section].data[*addr..]
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
        self.sections[self.plt_section].data.reserve((self.plt.len() + 1) * 16);
        self.sections[self.plt_section].data.extend(header);

        let entry = [
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x68, 0x00, 0x00, 0x00, 0x00, // push   $0x00000000
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmpq   0x0
        ];
        for _ in 0..self.plt.len() {
            self.sections[self.plt_section].data.extend(&entry);
        }
        for (symbol_ref, plt_index) in &self.plt {
            let entry = &mut self.sections[self.plt_section].data[16 * (plt_index + 1)..];
            let sym = self.symbols.get(*symbol_ref).unwrap();
            let got_plt_offset = sym.got_plt_offset().unwrap().try_into().unwrap();
            let plt_index: u32 = (*plt_index).try_into().unwrap();
            entry[2..].as_mut().write_u32::<LittleEndian>(got_plt_offset).unwrap();
            entry[7..].as_mut().write_u32::<LittleEndian>(plt_index).unwrap();
            // we need to jump over all of the entries that we wrote so far, and the header
            let plt_start_offset = (plt_index + 2) * 16;
            entry[12..].as_mut().write_u32::<LittleEndian>(plt_start_offset).unwrap();
        }
        self.sections[self.plt_section].sh.sh_size = self.sections[self.plt_section].data.len() as u64;
    }

    fn handle_special_symbols(&mut self) {
        // TODO: handle more edge cases
        if let Some(section_entry) = self.section_names.get(".init_array") {
            let init_array_start = self.symbol_names.get("__init_array_start");
            let init_array_end = self.symbol_names.get("__init_array_end");
            if let (Some(start), Some(end)) = (init_array_start, init_array_end) {
                let section = &self.sections[section_entry.index];
                let size = section.sh.sh_size;
                let addr = section.sh.sh_addr;
                for (s, v) in [(start, addr), (end, addr + size)] {
                    let sym = self.symbols.get_mut(SymbolRef { st_name: s.offset as u32 }).unwrap();
                    sym.st_shndx = section_entry.index as u16;
                    sym.st_value = v
                }
            }
        }
    }

    fn compute_tables(&mut self) -> Result<(), ErrorType> {
        let dyn_symtab_name = self.section_names.get_or_create(".dynsym").offset;
        let dyn_strtab_name = self.section_names.get_or_create(".dynstr").offset;
        let dyn_relocs_name = self.section_names.get_or_create(".rela.dyn").offset;
        let dynamic_name = self.section_names.get_or_create(".dynamic").offset;
        let symtab_name = self.section_names.get_or_create(".symtab").offset;
        let strtab_name = self.section_names.get_or_create(".strtab").offset;
        let shstrtab_name = self.section_names.get_or_create(".shstrtab").offset;

        // prepare .dynsym section and segment
        let dyn_sym_section_index = self.sections.len() as u32;
        let mut section = vec![];
        let syms = self.dyn_symbols.sorted_with_indexes();
        let mut last_local = 0;
        for (_, sym) in syms.values() {
            let st_bind = sym.st_info >> 4;
            sym.serialize(&mut section);
            if st_bind == STB_LOCAL {
                last_local += 1;
            }
        }
        let alignment = std::mem::align_of::<u64>() as u64;
        self.p_vaddr = round_to(self.p_vaddr, alignment);
        let len = section.len() as u64;
        let mut sh = SectionHeader {
            sh_name: dyn_symtab_name as u32,
            sh_type: SHT_DYNSYM,
            sh_size: len,
            sh_info: last_local,
            sh_entsize: size_of::<Sym>() as u64,
            sh_link: self.sections.len() as u32 + 1,
            sh_flags: SHF_ALLOC as u64,
            sh_offset: post_inc(&mut self.file_offset, len),
            sh_addralign: alignment,
            sh_addr: 0,
        };
        self.program_headers
            .push(get_program_header(&self.section_names, &mut sh, &mut self.p_vaddr).unwrap());
        try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &sh);
        self.sections.push(Section { sh, data: section });

        // prepare .dynstr section and segment
        let dyn_str_section_index = self.sections.len() as u32;
        let mut sec = self.dyn_symbol_names.section_header(dyn_strtab_name as u32);
        sec.sh.sh_flags |= SHF_ALLOC as u64;
        sec.sh.sh_offset = post_inc(&mut self.file_offset, sec.sh.sh_size);
        self.program_headers
            .push(get_program_header(&self.section_names, &mut sec.sh, &mut self.p_vaddr).unwrap());
        try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &sec.sh);
        self.sections.push(sec);

        // prepare .hash section
        let hash_syms = syms.iter().map(|(_, (_, s))| *s as &_).collect::<Vec<&Symbol>>();
        if self.hash_style == HashStyle::Sysv || self.hash_style == HashStyle::Both {
            let hash_name = self.section_names.get_or_create(".hash").offset;
            let mut sec = SymbolTable::hash_section(hash_name as u32, &hash_syms);
            sec.sh.sh_offset = post_inc(&mut self.file_offset, sec.sh.sh_size);
            sec.sh.sh_link = dyn_sym_section_index;
            self.program_headers.push(
                get_program_header(&self.section_names, &mut sec.sh, &mut self.p_vaddr).unwrap(),
            );
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &sec.sh);
            self.sections.push(sec);
        }
        if self.hash_style == HashStyle::Gnu || self.hash_style == HashStyle::Both {
            let hash_name = self.section_names.get_or_create(".gnu.hash").offset;
            let mut sec = SymbolTable::gnu_hash_section(hash_name as u32, &hash_syms);
            sec.sh.sh_offset = post_inc(&mut self.file_offset, sec.sh.sh_size);
            sec.sh.sh_link = dyn_sym_section_index;
            self.program_headers.push(
                get_program_header(&self.section_names, &mut sec.sh, &mut self.p_vaddr).unwrap(),
            );
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &sec.sh);
            self.sections.push(sec);
        }

        // prepare .rela.dyn section
        if !self.dyn_rels.is_empty() {
            let mut section = Vec::with_capacity(self.dyn_rels.len() * size_of::<Rela>());
            for (rela, symbol_ref) in &mut self.dyn_rels {
                if let Some(dyn_symbol_ref) = self.symbol_mapping.get(symbol_ref) {
                    let sym = syms[&dyn_symbol_ref.st_name].0 as u64;
                    rela.r_info += sym << 32;
                    rela.serialize(&mut section);
                }
            }
            let len = section.len() as u64;
            let alignment = std::mem::align_of::<u64>() as u64;
            self.p_vaddr = round_to(self.p_vaddr, alignment);
            let mut sh = SectionHeader {
                sh_name: dyn_relocs_name as u32,
                sh_type: SHT_RELA,
                sh_size: len,
                sh_entsize: size_of::<Rela>() as u64,
                sh_flags: SHF_ALLOC as u64,
                sh_offset: post_inc(&mut self.file_offset, len),
                sh_addralign: alignment,
                sh_link: dyn_sym_section_index,
                ..Default::default()
            };
            self.program_headers
                .push(get_program_header(&self.section_names, &mut sh, &mut self.p_vaddr).unwrap());
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &sh);
            self.sections.push(Section { sh, data: section });
        }

        // prepare .dynamic section and segment
        self.dyn_entries.push((DynTag::Null, 0));
        let mut section = Vec::with_capacity(self.dyn_entries.len() * 2 * size_of::<u64>());
        for entry in &self.dyn_entries {
            entry.serialize(&mut section);
        }
        let len = section.len() as u64;
        let alignment = std::mem::align_of::<u64>() as u64;
        self.p_vaddr = round_to(self.p_vaddr, alignment);
        let mut sh = SectionHeader {
            sh_name: dynamic_name as u32,
            sh_type: SHT_DYNAMIC,
            sh_size: len,
            sh_entsize: size_of::<u64>() as u64 * 2,
            sh_flags: (SHF_ALLOC | SHF_WRITE) as u64,
            sh_offset: post_inc(&mut self.file_offset, len),
            sh_addralign: alignment,
            sh_link: dyn_str_section_index,
            ..Default::default()
        };
        self.program_headers
            .push(get_program_header(&self.section_names, &mut sh, &mut self.p_vaddr).unwrap());
        self.sections.push(Section { sh, data: section });

        // serialize symbols and make sure that locals come first
        let mut section = vec![];
        let syms = self.symbols.sorted();
        let mut undefined_symbols = vec![];
        let mut last_local = 0;
        for sym in syms {
            let st_bind = sym.st_info >> 4;
            if sym.st_shndx as u32 == SHN_UNDEF && st_bind == STB_GLOBAL {
                let name = self.symbol_names.name(sym.st_name as usize).unwrap().to_string();
                if self.dyn_symbol_names.get(name.clone()).is_none() {
                    undefined_symbols.push(name);
                    continue;
                }
            }
            // since we now have an address for our sections, we can patch the
            // final value of all symbols
            sym.st_value +=
                self.sections.get(sym.st_shndx as usize).map(|s| s.sh.sh_addr).unwrap_or(0);
            sym.serialize(&mut section);
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
                sh_size: section.len() as u64,
                sh_info: last_local,
                sh_entsize: size_of::<Sym>() as u64,
                sh_link: self.sections.len() as u32 + 1,
                sh_offset: post_inc(&mut self.file_offset, section.len() as u64),
                ..Default::default()
            },
            data: section,
        });

        let mut sec = self.symbol_names.section_header(strtab_name as u32);
        sec.sh.sh_offset = post_inc(&mut self.file_offset, sec.sh.sh_size);
        self.sections.push(sec);
        let mut sec = self.section_names.section_header(shstrtab_name as u32);
        sec.sh.sh_offset = post_inc(&mut self.file_offset, sec.sh.sh_size);
        self.sections.push(sec);

        Ok(())
    }

    pub fn compute_synthesized_sections(&mut self) {
        self.compute_got();
        self.compute_got_plt();
        self.compute_plt();

        // only patch the first 4 sections, which are our special sections
        for section in &mut self.sections[..self.plt_section + 1] {
            section.sh.sh_offset = self.file_offset;
            if let Some(ph) =
                get_program_header(&self.section_names, &mut section.sh, &mut self.p_vaddr)
            {
                self.program_headers.push(ph);
            }
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &section.sh);
            self.file_offset += section.data.len() as u64;
        }
        self.patch_got_plt();
    }

    // elf header
    // section 1
    // section 2
    // section header 1
    // section header 2
    // program header 1
    // ...
    pub fn compute_sections(&mut self) -> Result<(), ErrorType> {
        // patch section and program headers, but skip the synthesized ones
        for section in &mut self.sections[self.plt_section + 1..] {
            section.sh.sh_offset = self.file_offset;
            if let Some(ph) =
                get_program_header(&self.section_names, &mut section.sh, &mut self.p_vaddr)
            {
                self.program_headers.push(ph);
            }
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, &section.sh);
            self.file_offset += section.data.len() as u64;
            if self.section_names.name(section.sh.sh_name as usize).unwrap().starts_with(".text") {
                self.eh.e_entry = section.sh.sh_addr;
            }
        }

        self.handle_special_symbols();

        // we need to first patch all section headers before we
        // serialize our symbols. This is because we need to set symbol values
        // based on the section they refer to.
        self.compute_tables()?;

        self.eh.e_shnum = self.sections.len() as u16;
        self.eh.e_phnum = self.program_headers.len() as u16;
        // last section is the section header string table
        self.eh.e_shstrndx = self.eh.e_shnum - 1;
        self.eh.e_shoff = self.file_offset;
        // the program header comes right after all the sections + headers
        self.eh.e_phoff =
            self.eh.e_shoff + (self.eh.e_shnum as usize * size_of::<SectionHeader>()) as u64;
        Ok(())
    }

    pub fn write_to_disk(mut self) {
        let mut offset = 0;
        log::trace!("0x{:x}: ---- elf header ----\n{:#?}", offset, self.eh);
        offset += self.eh.serialize(&mut self.out);
        for (i, section) in self.sections.iter().enumerate() {
            log::trace!(
                "0x{:x}: ---- section {} {:?} ----",
                offset,
                i,
                self.section_names.name(section.sh.sh_name as usize)
            );
            self.out.write_all(&section.data).unwrap();
            offset += section.data.len();
        }
        for (i, section) in self.sections.iter().enumerate() {
            log::trace!("0x{:x}: ---- section {} ----\n{:#?}", offset, i, section.sh);
            offset += section.sh.serialize(&mut self.out);
        }
        for (i, ph) in self.program_headers.iter().enumerate() {
            log::trace!("0x{:x}: ---- prog header {} ----\n{:#?}", offset, i, ph);
            offset += ph.serialize(&mut self.out);
        }
    }
}

const fn round_to(val: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return val;
    }
    let rem = val % multiple;
    val + if rem != 0 { multiple - rem } else { 0 }
}

fn get_program_header(
    names: &StringTable,
    sh: &mut SectionHeader,
    p_vaddr: &mut u64,
) -> Option<ProgramHeader> {
    if sh.sh_size != 0 && sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
        let write = if sh.sh_flags as u32 & SHF_WRITE == SHF_WRITE { PF_W } else { 0 };
        let exec = if sh.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR { PF_X } else { 0 };
        *p_vaddr = round_to(*p_vaddr, sh.sh_addralign);
        sh.sh_addr = *p_vaddr;
        Some(ProgramHeader {
            p_type: p_type(names, sh),
            p_flags: PF_R | write | exec,
            p_align: sh.sh_addralign,
            p_offset: sh.sh_offset,
            p_vaddr: *p_vaddr,
            p_paddr: post_inc(p_vaddr, sh.sh_size),
            p_filesz: if sh.sh_type == SHT_NOBITS { 0 } else { sh.sh_size },
            p_memsz: sh.sh_size,
        })
    } else {
        None
    }
}

fn try_add_dyn_entries(entries: &mut Vec<(DynTag, u64)>, names: &StringTable, sh: &SectionHeader) {
    let name = names.name(sh.sh_name as usize).unwrap();
    match name as &str {
        ".init" => entries.push((DynTag::Init, sh.sh_addr)),
        ".fini" => entries.push((DynTag::Fini, sh.sh_addr)),
        ".rela.dyn" => {
            entries.extend(&[
                (DynTag::Rela, sh.sh_addr),
                (DynTag::RelaEnt, sh.sh_entsize),
                (DynTag::RelaSize, sh.sh_size),
                (DynTag::RelaCount, 0),
            ]);
        }
        _ => match sh.sh_type {
            SHT_DYNSYM => {
                entries.extend(&[(DynTag::SymTab, sh.sh_addr), (DynTag::SymEnt, sh.sh_entsize)])
            }
            SHT_STRTAB => {
                entries.extend(&[(DynTag::StrTab, sh.sh_addr), (DynTag::StrSize, sh.sh_size)])
            }
            SHT_INIT_ARRAY => entries
                .extend(&[(DynTag::InitArray, sh.sh_addr), (DynTag::InitArraySize, sh.sh_size)]),
            SHT_FINI_ARRAY => entries
                .extend(&[(DynTag::FiniArray, sh.sh_addr), (DynTag::FiniArraySize, sh.sh_size)]),
            SHT_HASH => entries.push((DynTag::Hash, sh.sh_addr)),
            SHT_GNU_HASH => entries.push((DynTag::GnuHash, sh.sh_addr)),
            _ => {}
        },
    };
}

fn p_type(names: &StringTable, sh: &SectionHeader) -> u32 {
    match sh.sh_type {
        SHT_DYNAMIC => PT_DYNAMIC,
        _ if names.name(sh.sh_name as usize).unwrap() as &str == ".interp" => PT_INTERP,
        _ => PT_LOAD,
    }
}

fn format_list(v: &[String]) -> String {
    let mut s = String::from("[");
    s += &v.join(", ");
    s += "]";
    s
}

fn post_inc(v: &mut u64, inc: u64) -> u64 {
    let tmp = *v;
    *v += inc;
    tmp
}
