use crate::{error::ErrorType, name::Name, serialize::Serialize, symbol::Symbol};
use goblin::elf64::{
    header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT},
    program_header::{ProgramHeader, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD},
    reloc::{Rela, *},
    section_header::{
        SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_ABS, SHN_UNDEF, SHT_DYNAMIC,
        SHT_DYNSYM, SHT_FINI_ARRAY, SHT_GNU_HASH, SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS,
        SHT_PROGBITS, SHT_RELA, SHT_STRTAB,
    },
    sym::Sym,
};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    mem::{align_of, size_of},
    path::Path,
};

mod options;
pub use options::*;

mod section;
pub use section::Section;

mod chunk;

mod string_table;
pub use string_table::StringTable;

mod symbol_table;
pub use symbol_table::{GnuHashTable, HashTable, SymbolRef, SymbolTable};

use self::chunk::Chunk;

#[derive(Debug, Clone, Copy)]
pub struct SectionRef {
    /// The section index where a particular section was relocated to.
    index: usize,
    /// The chunk that the previous section resides in.
    chunk: usize,
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
    dyn_rels: Vec<Rela>,
    sections: Vec<Section>,
    got_len: usize,
    plt: HashMap<SymbolRef, usize>,
    got_plt: HashMap<SymbolRef, usize>,
    dyn_entries: Vec<(DynTag, u64)>,
    program_headers: Vec<ProgramHeader>,
    p_vaddr: u64,
    file_offset: u64,
    shstr_section: usize,
    sym_str_section: usize,
    dyn_sym_str_section: usize,
    sym_section: usize,
    dyn_sym_section: usize,
    got_section: usize,
    plt_section: usize,
    got_plt_section: usize,
    dynamic_section: usize,
    dyn_rel_section: usize,
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
        let (mut section_names, section_names_sh) = StringTable::with_name(".shstrtab");
        let (symbol_names, symbol_names_sh) =
            StringTable::new(section_names.get_or_create(".strtab").offset as u32);
        let (mut dyn_symbol_names, dyn_symbol_names_sh) =
            StringTable::new(section_names.get_or_create(".dynstr").offset as u32);
        let loader = options
            .dynamic_linker
            .to_str()
            .unwrap()
            .as_bytes()
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect::<Vec<u8>>();
        let interp_entry = dyn_symbol_names.get_or_create(
            options.dynamic_linker.file_name().unwrap().to_str().unwrap().to_string(),
        );
        let mut interp_section = Section::new(SectionHeader {
            sh_name: section_names.get_or_create(".interp").offset as u32,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC as u64,
            sh_size: loader.len() as u64,
            sh_addralign: 1,
            ..Default::default()
        });
        interp_section.add_chunk(loader.into());

        let section = SectionHeader {
            sh_type: SHT_PROGBITS,
            sh_flags: (SHF_ALLOC | SHF_WRITE) as u64,
            sh_addralign: size_of::<u64>() as u64,
            ..Default::default()
        };
        let mut got_section = section;
        got_section.sh_name = section_names.get_or_create(".got").offset as u32;
        let mut got_plt_section = section;
        got_plt_section.sh_name = section_names.get_or_create(".got.plt").offset as u32;
        let mut plt_section = section;
        plt_section.sh_name = section_names.get_or_create(".plt").offset as u32;

        let (symbols, symbols_sh) =
            SymbolTable::new(section_names.get_or_create(".symtab").offset as u32, false);
        let (dyn_symbols, dyn_symbols_sh) =
            SymbolTable::new(section_names.get_or_create(".dynsym").offset as u32, true);

        let dynamic_sh = SectionHeader {
            sh_name: section_names.get_or_create(".dynamic").offset as u32,
            sh_type: SHT_DYNAMIC,
            sh_entsize: size_of::<u64>() as u64 * 2,
            sh_flags: (SHF_ALLOC | SHF_WRITE) as u64,
            sh_addralign: align_of::<u64>() as u64,
            ..Default::default()
        };

        let dyn_rel_sh = SectionHeader {
            sh_name: section_names.get_or_create(".rela.dyn").offset as u32,
            sh_type: SHT_RELA,
            sh_entsize: size_of::<Rela>() as u64,
            sh_flags: SHF_ALLOC as u64,
            sh_addralign: align_of::<u64>() as u64,
            ..Default::default()
        };

        Ok(Self {
            out,
            hash_style: options.hash_style,
            eh,
            section_names,
            symbol_names,
            dyn_symbol_names,
            symbols,
            dyn_symbols,
            dyn_rels: vec![],
            sections: vec![
                SectionHeader::default().into(),
                section_names_sh.into(),
                symbol_names_sh.into(),
                dyn_symbol_names_sh.into(),
                interp_section,
                got_section.into(),
                got_plt_section.into(),
                plt_section.into(),
                symbols_sh.into(),
                dyn_symbols_sh.into(),
                dynamic_sh.into(),
                dyn_rel_sh.into(),
            ],
            // first entry reserved
            got_len: 1,
            plt: Default::default(),
            got_plt: Default::default(),
            dyn_entries: vec![(DynTag::Needed, interp_entry.offset as u64)],
            program_headers: vec![],
            p_vaddr: 0x40000,
            file_offset: size_of::<Header>() as u64,
            shstr_section: 1,
            sym_str_section: 2,
            dyn_sym_str_section: 3,
            sym_section: 8,
            dyn_sym_section: 9,
            got_section: 5,
            plt_section: 6,
            got_plt_section: 7,
            dynamic_section: 10,
            dyn_rel_section: 11,
        })
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
        let chunk = if entry.new {
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
            let mut sh = Section::new(sh);
            let ret = sh.add_chunk(Chunk::from(data.unwrap_or_default()));
            self.sections.push(sh);
            ret
        } else {
            let section = &mut self.sections[entry.index];
            section.sh_size += sh.sh_size;
            section.sh_addralign = std::cmp::max(section.sh_addralign, sh.sh_addralign);
            if let Some(data) = data {
                section.add_chunk(Chunk::from(data))
            } else {
                section.last_chunk_index()
            }
        };
        SectionRef { index: entry.index, chunk }
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

    fn chunk(&mut self, section_ref: SectionRef) -> &mut Chunk {
        self.sections[section_ref.index].chunk_mut(section_ref.chunk)
    }

    fn add_symbol_inner<'s>(
        mut elf_sym: Sym,
        chunk: Option<&mut Chunk>,
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
        let r = symbols
            .add_symbol(elf_sym, hash, gnu_hash, reference)
            .map_err(|e| ErrorType::Other(format!("{} {}", &name as &str, e)))?;
        if let Some(chunk) = chunk {
            if elf_sym.st_shndx != SHN_ABS as u16 {
                r.map(|sym| chunk.add_symbol(sym));
            }
        }
        Ok(r)
    }

    pub fn add_symbol<'s>(
        &mut self,
        elf_sym: Sym,
        sec_ref: Option<SectionRef>,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<Option<SymbolRef>, ErrorType> {
        let chunk = if let Some(s) = sec_ref {
            Some(self.sections[s.index].chunk_mut(s.chunk))
        } else {
            None
        };
        Self::add_symbol_inner(
            elf_sym,
            chunk,
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
        let chunk = if let Some(s) = sec_ref {
            Some(self.sections[s.index].chunk_mut(s.chunk))
        } else {
            None
        };
        let r = Self::add_symbol_inner(
            elf_sym,
            chunk,
            name,
            reference,
            &mut self.dyn_symbol_names,
            &mut self.dyn_symbols,
        );
        if let Ok(Some(dyn_ref)) = r {
            if let Some(entry) = self.symbol_names.get(name.to_string()) {
                self.symbols
                    .get_mut(SymbolRef { st_name: entry.offset as u32 })
                    .unwrap()
                    .set_dynamic(dyn_ref);
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
            if sym.st_shndx as u32 == SHN_UNDEF
                && (sym.is_global() || sym.is_weak())
                && sym.dynamic().is_none()
            {
                undefined.push(SymbolRef { st_name: *st_name });
            }
        }
        undefined
    }

    pub fn add_relocation(
        &mut self,
        reloc: Rela,
        sym_ref: SymbolRef,
        section_ref: SectionRef,
    ) -> Result<(), ErrorType> {
        let r_type = reloc.r_info as u32;
        match r_type as u32 {
            R_X86_64_8 | R_X86_64_16 | R_X86_64_PC16 | R_X86_64_PC8 => {
                return Err(ErrorType::Other(format!(
                    "Relocation {} not conforming to ABI.",
                    r_type
                )));
            }
            R_X86_64_GOT32
            | R_X86_64_GOTPCREL
            | R_X86_64_GOTOFF64
            | R_X86_64_GOTPC32
            | R_X86_64_GOTPCRELX
            | R_X86_64_REX_GOTPCRELX
            | R_X86_64_TLSGD
            | R_X86_64_GOTTPOFF => self.add_got_entry(sym_ref, r_type),
            R_X86_64_PLT32 => self.add_plt_entry(sym_ref),
            _ => {}
        }
        self.chunk(section_ref).add_relocation(reloc, sym_ref);
        Ok(())
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
        self.sections[self.got_section].sh_addr
    }

    pub fn plt_address(&self) -> u64 {
        self.sections[self.plt_section].sh_addr
    }

    pub fn add_needed(&mut self, so_name: &str) {
        let entry = self.dyn_symbol_names.get_or_create(so_name.to_string());
        if entry.new {
            self.dyn_entries.push((DynTag::Needed, entry.offset as u64));
        }
    }

    fn resize_got_section(&mut self) {
        let data = std::iter::repeat(0).take(size_of::<u64>() * self.got_len).collect::<Vec<u8>>();
        let section = &mut self.sections[self.got_section];
        section.sh_size = data.len() as u64;
        section.add_chunk(data.into());
    }

    fn resize_got_plt_section(&mut self) {
        let data = std::iter::repeat(0)
            .take(size_of::<u64>() * (self.got_plt.len() + 3))
            .collect::<Vec<u8>>();
        let section = &mut self.sections[self.got_plt_section];
        section.sh_size = data.len() as u64;
        section.add_chunk(data.into());
    }

    fn patch_got_plt(&mut self) {
        use byteorder::{LittleEndian, WriteBytesExt};

        let plt_address = self.plt_address();
        for (sym, addr) in &self.got_plt {
            let sym = self.symbols.get(*sym).unwrap();
            // 16 to skip the header, another 16 for all entries before plt_index, and then another 11
            let plt_index = sym.plt_index().unwrap();
            self.sections[self.got_plt_section].chunk_mut(0)[*addr..]
                .as_mut()
                .write_u64::<LittleEndian>(plt_address + 16 * (plt_index as u64 + 1) + 11)
                .unwrap();
        }
    }

    fn resize_plt_section(&mut self) {
        let mut plt_chunk = vec![];
        let header = [
            0xff, 0x35, 0x00, 0x00, 0x00, 0x00, // pushq  0x0(%rip)
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x90, 0x90, 0x90, 0x90, // nop nop nop nop
        ];
        plt_chunk.reserve((self.plt.len() + 1) * 16);
        plt_chunk.extend(header);

        let entry = [
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmpq   *0x0(%rip)
            0x68, 0x00, 0x00, 0x00, 0x00, // push   $0x00000000
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmpq   0x0
        ];
        for _ in 0..self.plt.len() {
            plt_chunk.extend(&entry);
        }
        let section = &mut self.sections[self.plt_section];
        section.sh_size = plt_chunk.len() as u64;
        section.add_chunk(plt_chunk.into());
    }

    fn handle_special_symbols(&mut self) {
        // TODO: handle more edge cases
        if let Some(e) = self.symbol_names.get("_GLOBAL_OFFSET_TABLE_") {
            if let Some(s) = self.symbols.get_mut(SymbolRef { st_name: e.offset as u32 }) {
                s.st_shndx = SHN_ABS as u16;
            };
        }
        if self.section_names.get(".init_array").is_some() {
            let init_array_start = self.symbol_names.get("__init_array_start");
            let init_array_end = self.symbol_names.get("__init_array_end");
            if let (Some(start), Some(end)) = (init_array_start, init_array_end) {
                for s in [start, end] {
                    let sym = self.symbols.get_mut(SymbolRef { st_name: s.offset as u32 }).unwrap();
                    sym.st_shndx = SHN_ABS as u16;
                }
            }
        }
    }

    fn compute_tables(&mut self) {
        // populate symbol sections
        for (sh, syms, link) in [
            (self.sym_section, &mut self.symbols, self.sym_str_section),
            (self.dyn_sym_section, &mut self.dyn_symbols, self.dyn_sym_str_section),
        ] {
            let section = &mut self.sections[sh];
            section.add_chunk(syms.chunk());
            section.sh_info = syms.num_locals() as u32;
            section.sh_link = link as u32;
        }

        // populate string sections
        for (sh, strs) in [
            (self.shstr_section, &mut self.section_names),
            (self.sym_str_section, &mut self.symbol_names),
            (self.dyn_sym_str_section, &mut self.dyn_symbol_names),
        ] {
            let section = &mut self.sections[sh];
            section.add_chunk(strs.chunk());
        }

        // populate dynamic section
        let section = &mut self.sections[self.dynamic_section];
        let mut data = Vec::with_capacity(section.sh_size as usize);
        self.dyn_entries.serialize(&mut data);
        section.add_chunk(data.into());
        section.sh_link = self.dyn_sym_str_section as u32;

        // populate dyn.rel section
        let mut data = Vec::with_capacity(self.sections[self.dyn_rel_section].sh_size as usize);
        let got_addr = self.got_address();
        for dyn_rel in &mut self.dyn_rels {
            dyn_rel.r_offset += got_addr;
            dyn_rel.serialize(&mut data);
        }
        let section = &mut self.sections[self.dyn_rel_section];
        section.add_chunk(data.into());
        section.sh_link = self.dyn_sym_section as u32;
    }

    pub fn assign_section_addresses(&mut self) {
        self.resize_got_section();
        self.resize_got_plt_section();
        self.resize_plt_section();

        self.sections[self.sym_section].sh_size = self.symbols.total_len() as u64;
        self.sections[self.dyn_sym_section].sh_size = self.dyn_symbols.total_len() as u64;
        let sorted = self.dyn_symbols.sorted();
        if self.hash_style == HashStyle::Sysv || self.hash_style == HashStyle::Both {
            let hash_name = self.section_names.get_or_create(".hash").offset;
            let mut sec = SymbolTable::hash_section(hash_name as u32, &sorted[..]);
            sec.sh_link = self.dyn_sym_section as u32;
            self.sections.push(sec);
        }
        if self.hash_style == HashStyle::Gnu || self.hash_style == HashStyle::Both {
            let hash_name = self.section_names.get_or_create(".gnu.hash").offset;
            let mut sec = SymbolTable::gnu_hash_section(hash_name as u32, &sorted[..]);
            sec.sh_link = self.dyn_sym_section as u32;
            self.sections.push(sec);
        }

        self.sections[self.shstr_section].sh_size = self.section_names.total_len() as u64;
        self.sections[self.sym_str_section].sh_size = self.symbol_names.total_len() as u64;
        self.sections[self.dyn_sym_str_section].sh_size = self.dyn_symbol_names.total_len() as u64;

        for (sym, dyn_sym) in self.symbols.values().filter_map(|s| s.dynamic().map(|d| (s, d))) {
            if let Some(offset) = sym.got_offset() {
                // XXX: this should be more efficient
                let index = sorted
                    .iter()
                    .enumerate()
                    .find(|(_, s)| s.st_name == dyn_sym.st_name)
                    .map(|(i, _)| i)
                    .unwrap();
                self.dyn_rels.push(Rela {
                    r_offset: offset as u64,
                    r_info: ((index << 32) + R_X86_64_GLOB_DAT as usize) as u64,
                    r_addend: 0,
                });
            }
        }
        self.sections[self.dyn_rel_section].sh_size =
            (self.dyn_rels.len() * size_of::<Rela>()) as u64;

        // calculate how many dyntags we have, so that we know how big our dynamic section is
        for section in &mut self.sections {
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, section);
        }
        self.sections[self.dynamic_section].sh_size =
            (self.dyn_entries.len() * 2 * size_of::<u64>()) as u64;

        for section in &mut self.sections {
            section.sh_offset = post_inc(&mut self.file_offset, section.size_on_disk());
            if let Some(ph) = get_program_header(&self.section_names, section, &mut self.p_vaddr) {
                self.program_headers.push(ph);
            }
        }

        self.patch_got_plt();
    }

    fn handle_relocations(&mut self) {
        let got_address = self.got_address();
        let plt_address = self.plt_address();
        // first patch symbol values
        for (i, section) in &mut self.sections.iter_mut().enumerate().skip(1) {
            section.patch_symbol_values(i as u16, &mut self.symbols);
        }
        for section in &mut self.sections.iter_mut().skip(1) {
            for chunk in section.chunks_mut() {
                chunk.apply_relocations(got_address, plt_address, &self.symbols);
            }
        }
    }

    // elf header
    // section 1
    // section 2
    // section header 1
    // section header 2
    // program header 1
    // ...
    pub fn compute_sections(&mut self) {
        self.assign_section_addresses();

        self.handle_special_symbols();

        self.handle_relocations();

        self.compute_tables();

        if let Some(entry) = self.symbol_names.get("_start") {
            self.eh.e_entry = self.symbols[&(entry.offset as u32)].st_value;
        }
        self.eh.e_shnum = self.sections.len() as u16;
        self.eh.e_phnum = self.program_headers.len() as u16;
        self.eh.e_shstrndx = self.shstr_section as u16;
        self.eh.e_shoff = self.file_offset;
        // the program header comes right after all the sections + headers
        self.eh.e_phoff =
            self.eh.e_shoff + (self.eh.e_shnum as usize * size_of::<SectionHeader>()) as u64;
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
                self.section_names.name(section.sh_name as usize)
            );
            for chunk in section.chunks() {
                self.out.write_all(&chunk).unwrap();
            }
            offset += section.size_on_disk() as usize;
        }
        for (i, section) in self.sections.iter().enumerate() {
            log::trace!(
                "0x{:x}: ---- section {} ----\n{:#?}",
                offset,
                i,
                &section as &SectionHeader
            );
            offset += section.serialize(&mut self.out);
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
    sh: &mut Section,
    p_vaddr: &mut u64,
) -> Option<ProgramHeader> {
    if sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
        let write = if sh.sh_flags as u32 & SHF_WRITE == SHF_WRITE { PF_W } else { 0 };
        let exec = if sh.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR { PF_X } else { 0 };
        *p_vaddr = round_to(*p_vaddr, sh.sh_addralign);
        sh.set_address(*p_vaddr);
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

fn post_inc(v: &mut u64, inc: u64) -> u64 {
    let tmp = *v;
    *v += inc;
    tmp
}
