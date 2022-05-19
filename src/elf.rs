use crate::{
    error::ErrorType,
    name::Name,
    serialize::Serialize,
    symbol::Symbol,
    utils::{is_some_with, map_if_eq},
};
use goblin::elf64::{
    header::{Header, ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_EXEC, EV_CURRENT},
    program_header::{ProgramHeader, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_PHDR},
    reloc::{r_type, Rela, *},
    section_header::{
        SectionHeader, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_ABS, SHN_UNDEF, SHT_DYNAMIC,
        SHT_DYNSYM, SHT_FINI_ARRAY, SHT_GNU_HASH, SHT_HASH, SHT_INIT_ARRAY, SHT_PROGBITS, SHT_RELA,
        SHT_STRTAB,
    },
    sym::Sym,
};
use std::{
    cmp::Ordering,
    collections::HashMap,
    convert::TryInto,
    fs::File,
    io::Write,
    mem::{align_of, size_of},
    os::unix::prelude::PermissionsExt,
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

const PLT_ENTRY_JMP_INSTR_SIZE: isize = 6;
const PLT_ENTRY_PUSH_INSTR_SIZE: usize = 5;
// The PLT header is just as big.
const PLT_ENTRY_SIZE: usize = 16;

#[derive(Clone, Copy, Debug)]
pub enum DynTag {
    /// Marks end of dynamic section
    Null = 0,
    /// Name of needed library
    Needed = 1,
    /// Size in bytes of PLT relocs
    PltRelSz = 2,
    /// Processor defined value
    PltGot = 3,
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
    PltRel = 20,
    /// For debugging, unspecified
    Debug = 21,
    /// Reloc might modify .text
    Textrel = 22,
    /// Address of PLT relocs
    JmpRel = 23,
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
    plt_rels: Vec<Rela>,
    sections: Vec<Section>,
    got_len: usize,
    plt: HashMap<SymbolRef, usize>,
    got_plt: HashMap<SymbolRef, usize>,
    dyn_entries: Vec<(DynTag, u64)>,
    program_headers: Vec<ProgramHeader>,
    p_vaddr: u64,
    start_p_vaddr: u64,
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
    plt_rel_section: usize,
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
            e_phoff: size_of::<Header>() as u64,
            // patched in `Writer::write`
            e_entry: 0,
            e_phnum: 0,
            e_shnum: 0,
            e_shoff: 0,
            e_shstrndx: 0,
        };
        let (mut section_names, section_names_sh) = StringTable::with_name(".shstrtab");
        let (symbol_names, symbol_names_sh) =
            StringTable::new(section_names.get_or_create(".strtab").offset as u32);
        let (mut dyn_symbol_names, mut dyn_symbol_names_sh) =
            StringTable::new(section_names.get_or_create(".dynstr").offset as u32);
        dyn_symbol_names_sh.sh_flags = SHF_ALLOC as u64;
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
        plt_section.sh_flags = (SHF_ALLOC | SHF_EXECINSTR) as u64;
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

        let plt_rel_sh = SectionHeader {
            sh_name: section_names.get_or_create(".rela.plt").offset as u32,
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
            plt_rels: vec![],
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
                plt_rel_sh.into(),
            ],
            // first entry reserved
            got_len: 1,
            plt: Default::default(),
            got_plt: Default::default(),
            dyn_entries: vec![(DynTag::Needed, interp_entry.offset as u64)],
            program_headers: vec![],
            p_vaddr: 0x200000,
            start_p_vaddr: 0x200000,
            file_offset: 0,
            // XXX: I should really come up with a better way to store quick
            // references to these special sections
            shstr_section: 1,
            sym_str_section: 2,
            dyn_sym_str_section: 3,
            got_section: 5,
            got_plt_section: 6,
            plt_section: 7,
            sym_section: 8,
            dyn_sym_section: 9,
            dynamic_section: 10,
            dyn_rel_section: 11,
            plt_rel_section: 12,
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
    ) -> Result<SymbolRef, ErrorType> {
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
                chunk.add_symbol(r);
            }
        }
        Ok(r)
    }

    pub fn add_symbol<'s>(
        &mut self,
        mut elf_sym: Sym,
        sec_ref: Option<SectionRef>,
        name: &'s str,
        reference: &'d Path,
    ) -> Result<Option<SymbolRef>, ErrorType> {
        let chunk = if let Some(s) = sec_ref {
            // since smybol should point to the new section we're creating
            elf_sym.st_shndx = s.index as u16;
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
        .map(Some)
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
        if let Ok(dyn_ref) = r {
            if let Some(entry) = self.symbol_names.get(name.to_string()) {
                self.symbols
                    .get_mut(SymbolRef::Named(entry.offset as u32))
                    .unwrap()
                    .set_dynamic(dyn_ref);
            }
        }
        r.map(Some)
    }

    pub fn symbol(&self, sym: SymbolRef) -> Symbol<'_> {
        *self.symbols.get(sym).unwrap()
    }

    pub fn symbol_name(&self, sym: SymbolRef) -> &str {
        if let SymbolRef::Named(st_name) = sym {
            self.symbol_names.name(st_name as usize).unwrap()
        } else {
            ""
        }
    }

    pub fn undefined_symbols(&self) -> Vec<SymbolRef> {
        let mut undefined = vec![];
        for (st_name, sym) in self.symbols.named().iter() {
            if sym.st_shndx as u32 == SHN_UNDEF
                && (sym.is_global() || sym.is_weak())
                && sym.dynamic().is_none()
            {
                undefined.push(SymbolRef::Named(*st_name));
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
        let r_type = r_type(reloc.r_info);
        match r_type {
            R_X86_64_8 | R_X86_64_16 | R_X86_64_PC16 | R_X86_64_PC8 => {
                return Err(ErrorType::Other(format!(
                    "Relocation {} not conforming to ABI.",
                    r_type
                )));
            }
            _ => {}
        }
        self.chunk(section_ref).add_relocation(reloc, sym_ref);
        Ok(())
    }

    pub fn got_address(&self) -> u64 {
        self.sections[self.got_section].sh_addr
    }

    pub fn plt_address(&self) -> u64 {
        self.sections[self.plt_section].sh_addr
    }

    pub fn got_plt_address(&self) -> u64 {
        self.sections[self.got_plt_section].sh_addr
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

    fn patch_plt_and_got_plt(&mut self) {
        use byteorder::{LittleEndian, WriteBytesExt};

        let plt_address = self.plt_address();
        let got_plt_address = self.got_plt_address();
        let relative_got_plt = got_plt_address as i64 - plt_address as i64;

        // first we patch the header to point to the correct `.got.plt` entries
        let plt_entry_chunk = self.sections[self.plt_section].chunk_mut(0);
        // first address is `.got.plt[1]`
        let got_entry_size = size_of::<u64>() as i64;
        plt_entry_chunk[2..]
            .as_mut()
            .write_i32::<LittleEndian>(
                (relative_got_plt + got_entry_size - PLT_ENTRY_JMP_INSTR_SIZE as i64)
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        // the second address is `.got.plt[2]`
        plt_entry_chunk[PLT_ENTRY_JMP_INSTR_SIZE as usize + 2..]
            .as_mut()
            .write_i32::<LittleEndian>(
                (relative_got_plt + 2 * got_entry_size - 2 * PLT_ENTRY_JMP_INSTR_SIZE as i64)
                    .try_into()
                    .unwrap(),
            )
            .unwrap();

        for (sym, offset) in &self.got_plt {
            let sym = self.symbols.get(*sym).unwrap();
            let plt_entry_addr = plt_entry_addr(plt_address, sym.plt_index().unwrap());
            // + `PLT_ENTRY_JMP_INSTR_SIZE` since initially we want to jump back past the `jmp`
            // instruction of the plt entry
            self.sections[self.got_plt_section].chunk_mut(0)[*offset..]
                .as_mut()
                .write_i64::<LittleEndian>(plt_entry_addr + PLT_ENTRY_JMP_INSTR_SIZE as i64)
                .unwrap();

            // we now patch multiple things of the PLT entry, such as:
            //   1. the `jmp` instruction, which will point to a corresponding `.got.plt` entry
            let plt_entry_offset = (plt_entry_addr as u64 - plt_address) as usize;
            let got_plt_entry_addr = (*offset as u64 + got_plt_address) as isize;
            let relative_got_plt_addr =
                (got_plt_entry_addr - plt_entry_addr as isize - PLT_ENTRY_JMP_INSTR_SIZE)
                    .try_into()
                    .unwrap();
            let plt_entry_chunk = self.sections[self.plt_section].chunk_mut(0);
            plt_entry_chunk[plt_entry_offset + 2..]
                .as_mut()
                .write_i32::<LittleEndian>(relative_got_plt_addr)
                .unwrap();

            //   2. the "relocation offset" of the `push` instruction
            let relocation_offset = sym.relocation_offset().unwrap();
            plt_entry_chunk[plt_entry_offset + PLT_ENTRY_JMP_INSTR_SIZE as usize + 1..]
                .as_mut()
                .write_u32::<LittleEndian>(relocation_offset as u32)
                .unwrap();

            //   3. patch the last jmp instruction to point to the start of .plt
            let plt0 = plt_address as i64 - (plt_entry_addr + PLT_ENTRY_SIZE as i64);
            plt_entry_chunk[plt_entry_offset
                + PLT_ENTRY_JMP_INSTR_SIZE as usize
                + PLT_ENTRY_PUSH_INSTR_SIZE
                + 1..]
                .as_mut()
                .write_i32::<LittleEndian>(plt0.try_into().unwrap())
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
        plt_chunk.reserve((self.plt.len() + 1) * PLT_ENTRY_SIZE);
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
        let got_plt_addr = self.got_plt_address();
        if let Some(e) = self.symbol_names.get("_GLOBAL_OFFSET_TABLE_") {
            if let Some(s) = self.symbols.get_mut(SymbolRef::Named(e.offset as u32)) {
                s.st_shndx = self.got_plt_section as u16;
                s.st_value = got_plt_addr;
            };
        }
        let symbols = &mut self.symbols;
        for section in &mut self.sections {
            if is_some_with(self.section_names.sh_name(".init_array"), &section.sh_name) {
                if let Some(s) = self.symbol_names.get("__init_array_start") {
                    section.chunk_mut(0).add_symbol(SymbolRef::Named(s.offset as u32));
                }
                if let Some(s) = self.symbol_names.get("__init_array_end") {
                    let sym_ref = SymbolRef::Named(s.offset as u32);
                    symbols.get_mut(sym_ref).unwrap().st_value = section.size_on_disk();
                    section.chunk_mut(section.last_chunk_index()).add_symbol(sym_ref);
                }
            } else if is_some_with(self.section_names.sh_name(".fini_array"), &section.sh_name) {
                if let Some(s) = self.symbol_names.get("__fini_array_start") {
                    section.chunk_mut(0).add_symbol(SymbolRef::Named(s.offset as u32));
                }
                if let Some(s) = self.symbol_names.get("__fini_array_end") {
                    let sym_ref = SymbolRef::Named(s.offset as u32);
                    symbols.get_mut(sym_ref).unwrap().st_value = section.size_on_disk();
                    section.chunk_mut(section.last_chunk_index()).add_symbol(sym_ref);
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

        // populate .rela.{dyn,plt} sections
        let got_addr = self.got_address();
        let got_plt_addr = self.got_plt_address();
        for (section_index, rels) in
            [(self.dyn_rel_section, &mut self.dyn_rels), (self.plt_rel_section, &mut self.plt_rels)]
        {
            let mut data = Vec::with_capacity(self.sections[section_index].sh_size as usize);
            for rel in rels {
                match r_type(rel.r_info) {
                    R_X86_64_GLOB_DAT => rel.r_offset += got_addr,
                    R_X86_64_JUMP_SLOT => rel.r_offset += got_plt_addr,
                    _ => {}
                }
                rel.serialize(&mut data);
            }
            let section = &mut self.sections[section_index];
            section.add_chunk(data.into());
            section.sh_link = self.dyn_sym_section as u32;
        }
    }

    fn sort_sections(&mut self) {
        let null_sect = self.sections.remove(0);
        self.sections.sort_unstable_by(section_cmp);
        self.sections.insert(0, null_sect);
        for (i, section) in self.sections.iter().enumerate() {
            let sh_name = section.sh_name;
            for (index, section) in [
                (&mut self.shstr_section, ".shstrtab"),
                (&mut self.sym_str_section, ".strtab"),
                (&mut self.dyn_sym_str_section, ".dynstr"),
                (&mut self.sym_section, ".symtab"),
                (&mut self.dyn_sym_section, ".dynsym"),
                (&mut self.got_section, ".got"),
                (&mut self.plt_section, ".plt"),
                (&mut self.got_plt_section, ".got.plt"),
                (&mut self.dynamic_section, ".dynamic"),
                (&mut self.dyn_rel_section, ".rela.dyn"),
                (&mut self.plt_rel_section, ".rela.plt"),
            ] {
                let res = map_if_eq(self.section_names.sh_name(section), &sh_name, |_| {
                    *index = i;
                });
                if res.is_some() {
                    break;
                }
            }
        }
        for section in &mut self.sections {
            let sh_name = section.sh_name;
            let dyn_sym_section = self.dyn_sym_section as u32;
            map_if_eq(self.section_names.sh_name(".hash"), &sh_name, |_| {
                section.sh_link = dyn_sym_section;
            });
        }
    }

    fn scan_relocations(&mut self) {
        for section in &mut self.sections {
            for chunk in section.chunks_mut() {
                for (reloc, sym_ref) in chunk.relocations_mut() {
                    let r_type = reloc.r_info as u32;
                    match r_type as u32 {
                        R_X86_64_GOT32
                        | R_X86_64_GOTPCREL
                        | R_X86_64_GOTOFF64
                        | R_X86_64_GOTPC32
                        | R_X86_64_GOTPCRELX
                        | R_X86_64_REX_GOTPCRELX
                        | R_X86_64_TLSGD
                        | R_X86_64_GOTTPOFF => {
                            let sym = self.symbols.get_mut(*sym_ref).unwrap();
                            if sym.got_offset().is_none() {
                                sym.set_got_offset(self.got_len * size_of::<u64>());
                                // For TLSGD relocations we need to allocate two slots
                                self.got_len +=
                                    if sym.is_tls() && r_type == R_X86_64_TLSGD { 2 } else { 1 };
                            }
                        }
                        R_X86_64_PLT32 => {
                            let sym = self.symbols.get_mut(*sym_ref).unwrap();
                            if sym.dynamic().is_some() {
                                let len = self.plt.len();
                                let index = *self.plt.entry(*sym_ref).or_insert(len);
                                let len = self.got_plt.len() + 3;
                                let offset =
                                    *self.got_plt.entry(*sym_ref).or_insert(len * size_of::<u64>());
                                sym.set_got_plt_offset(offset);
                                sym.set_plt_index(index);
                            } else {
                                // replace PLT32 with PC32 since the symbol is local to us
                                reloc.r_info -= r_type as u64;
                                reloc.r_info += R_X86_64_PC32 as u64;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn assign_section_addresses(&mut self) {
        self.scan_relocations();

        self.resize_got_section();
        self.resize_got_plt_section();
        self.resize_plt_section();

        self.sections[self.sym_section].sh_size = self.symbols.total_len() as u64;
        self.sections[self.dyn_sym_section].sh_size = self.dyn_symbols.total_len() as u64;
        let sorted = self.dyn_symbols.sorted();
        if self.hash_style == HashStyle::Sysv || self.hash_style == HashStyle::Both {
            let hash_name = self.section_names.get_or_create(".hash").offset;
            let sec = SymbolTable::hash_section(hash_name as u32, &sorted[..]);
            self.sections.push(sec);
        }
        // TODO: not working
        if self.hash_style == HashStyle::Gnu {
            let hash_name = self.section_names.get_or_create(".gnu.hash").offset;
            let sec = SymbolTable::gnu_hash_section(hash_name as u32, &sorted[..]);
            self.sections.push(sec);
        }

        self.sections[self.shstr_section].sh_size = self.section_names.total_len() as u64;
        self.sections[self.sym_str_section].sh_size = self.symbol_names.total_len() as u64;
        self.sections[self.dyn_sym_str_section].sh_size = self.dyn_symbol_names.total_len() as u64;

        for (sym, dyn_sym) in
            self.symbols.named_mut().values_mut().filter_map(|s| s.dynamic().map(|d| (s, d)))
        {
            let mut calculated_index = None;
            let mut index = || {
                if let Some(index) = calculated_index {
                    index
                } else {
                    let index = sorted
                        .iter()
                        .enumerate()
                        .find(|(_, s)| s.st_name == dyn_sym.st_name())
                        .map(|(i, _)| i)
                        .unwrap();
                    calculated_index = Some(index);
                    index
                }
            };
            if let Some(offset) = sym.got_offset() {
                self.dyn_rels.push(rela(offset, index(), R_X86_64_GLOB_DAT));
            }
            if let Some(offset) = sym.got_plt_offset() {
                sym.set_relocation_offset(self.plt_rels.len());
                self.plt_rels.push(rela(offset, index(), R_X86_64_JUMP_SLOT));
            }
        }
        self.sections[self.dyn_rel_section].sh_size =
            (self.dyn_rels.len() * size_of::<Rela>()) as u64;

        self.sections[self.plt_rel_section].sh_size =
            (self.plt_rels.len() * size_of::<Rela>()) as u64;

        // calculate how many dyntags we have, so that we know how big our dynamic section is
        // + 1 for the null entry
        let extra_dyn_entries =
            self.sections.iter().map(|sh| dyn_entries(&self.section_names, sh)).sum::<usize>() + 1;
        self.sections[self.dynamic_section].sh_size =
            ((self.dyn_entries.len() + extra_dyn_entries) * 2 * size_of::<u64>()) as u64;

        self.sort_sections();

        self.generate_program_headers();

        self.add_dyn_entries();

        self.patch_plt_and_got_plt();
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
    // program header 1
    // program header 2
    // section 1
    // section 2
    // section header 1
    // section header 2
    // ...
    pub fn compute_sections(&mut self) {
        self.assign_section_addresses();

        self.handle_special_symbols();

        self.handle_relocations();

        self.compute_tables();

        if let Some(entry) = self.symbol_names.get("_start") {
            self.eh.e_entry = self.symbols[SymbolRef::Named(entry.offset as u32)].st_value;
        }
        self.eh.e_shnum = self.sections.len() as u16;
        self.eh.e_phnum = self.program_headers.len() as u16;
        self.eh.e_shstrndx = self.shstr_section as u16;
        self.eh.e_shoff = self.file_offset;

        // patch the PHDR program header now that we have computed everything
        let ph = &mut self.program_headers[0];
        ph.p_offset = self.eh.e_phoff;
        ph.p_memsz = (self.eh.e_phnum * self.eh.e_phentsize) as u64;
        ph.p_filesz = ph.p_memsz;
        ph.p_vaddr = self.eh.e_phoff + self.start_p_vaddr;
        ph.p_paddr = ph.p_vaddr;
    }

    pub fn write_to_disk(mut self) {
        let mut offset = 0;
        log::trace!("0x{:x}: ---- elf header ----\n{:#?}", offset, self.eh);
        offset += self.eh.serialize(&mut self.out);
        for (i, ph) in self.program_headers.iter().enumerate() {
            log::trace!("0x{:x}: ---- prog header {} ----\n{:#?}", offset, i, ph);
            offset += ph.serialize(&mut self.out);
        }
        for (i, section) in self.sections.iter().enumerate() {
            // add the necessary padding between aligned sections
            if offset < section.sh_offset as usize {
                self.out
                    .write_all(
                        &std::iter::repeat(0)
                            .take(section.sh_offset as usize - offset)
                            .collect::<Vec<u8>>(),
                    )
                    .unwrap();
                offset = section.sh_offset as usize;
            }
            log::trace!(
                "0x{:x}: ---- section {} {:?} ----",
                offset,
                i,
                self.section_names.name(section.sh_name as usize)
            );
            for chunk in section.chunks() {
                self.out.write_all(chunk).unwrap();
            }
            offset += section.size_on_disk() as usize;
        }
        for (i, section) in self.sections.iter().enumerate() {
            log::trace!(
                "0x{:x}: ---- section {} ----\n{:#?}",
                offset,
                i,
                section as &SectionHeader
            );
            offset += section.serialize(&mut self.out);
        }
        let mut perm = self.out.metadata().unwrap().permissions();
        perm.set_mode(0o755);
        self.out.set_permissions(perm).unwrap();
    }

    fn count_program_headers(&self) -> usize {
        let mut count = 0;
        let mut flags = 0;
        for sh in self.sections.iter().skip(1) {
            if sh.sh_flags != flags {
                if sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
                    count += 1;
                }
                flags = sh.sh_flags;
            }
        }
        // 3 == INTERP, DYNAMIC, PHDR
        count + 3
    }

    fn generate_program_headers(&mut self) {
        let program_headers_size =
            (self.count_program_headers() * self.eh.e_phentsize as usize) as u64;
        let mut first_load_data = Some(program_headers_size + size_of::<Header>() as u64);
        let mut flags = 0;
        let mut program_header = None;
        for sh in self.sections.iter_mut().skip(1) {
            let old_p_vaddr = self.p_vaddr;
            if sh.sh_flags != flags {
                // push old program header
                if let Some(ph) = program_header.take() {
                    self.program_headers.push(ph);
                }

                // this function deals with sh_offset for us. if we don't
                // get a header, then we have to deal with it
                program_header = get_load_program_header(
                    sh,
                    &mut self.file_offset,
                    &mut self.p_vaddr,
                    &mut first_load_data,
                );
                if program_header.is_none() {
                    sh.sh_offset = post_inc(&mut self.file_offset, sh.size_on_disk());
                }
                flags = sh.sh_flags;
            } else {
                sh.sh_offset = post_inc(&mut self.file_offset, sh.size_on_disk());
                if let Some(ph) = program_header.as_mut() {
                    ph.p_filesz += sh.size_on_disk();
                    ph.p_memsz += sh.sh_size;
                    sh.set_address(self.p_vaddr);
                    self.p_vaddr += sh.sh_size;
                }
            }
            if let Some(p_type) = p_type(&self.section_names, sh) {
                let write = if sh.sh_flags as u32 & SHF_WRITE == SHF_WRITE { PF_W } else { 0 };
                // for .interp or .dynamic we have some extra program headers we want to generate
                self.program_headers.insert(
                    0,
                    ProgramHeader {
                        p_type,
                        p_flags: PF_R | write,
                        p_align: sh.sh_addralign,
                        p_offset: sh.sh_offset,
                        p_vaddr: old_p_vaddr,
                        p_paddr: old_p_vaddr,
                        p_filesz: sh.size_on_disk(),
                        p_memsz: sh.sh_size,
                    },
                )
            }
        }
        self.program_headers.insert(
            0,
            ProgramHeader {
                p_type: PT_PHDR,
                p_flags: PF_R,
                p_offset: 0,
                p_vaddr: 0,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_align: align_of::<u64>() as u64,
            },
        );
    }

    fn add_dyn_entries(&mut self) {
        for sh in &self.sections {
            try_add_dyn_entries(&mut self.dyn_entries, &self.section_names, sh);
        }
        self.dyn_entries.push((DynTag::Null, 0));
    }
}

const fn rela(offset: usize, index: usize, ty: u32) -> Rela {
    Rela { r_offset: offset as u64, r_info: ((index << 32) + ty as usize) as u64, r_addend: 0 }
}

const fn round_to(val: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return val;
    }
    let rem = val % multiple;
    val + if rem != 0 { multiple - rem } else { 0 }
}

const PAGE_ALIGNMENT: u64 = 0x1000;

fn get_load_program_header(
    sh: &mut Section,
    file_offset: &mut u64,
    p_vaddr: &mut u64,
    extra_data: &mut Option<u64>,
) -> Option<ProgramHeader> {
    if sh.sh_flags as u32 & SHF_ALLOC == SHF_ALLOC {
        let first_load = extra_data.is_some();
        let extra_data = extra_data.take().unwrap_or_default();
        let write = if sh.sh_flags as u32 & SHF_WRITE == SHF_WRITE { PF_W } else { 0 };
        let exec = if sh.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR { PF_X } else { 0 };
        *p_vaddr = round_to(*p_vaddr, PAGE_ALIGNMENT);
        sh.set_address(*p_vaddr + extra_data);
        *file_offset = round_to(*file_offset, PAGE_ALIGNMENT);
        let sh_size_on_disk = sh.size_on_disk() + extra_data;
        sh.sh_offset = post_inc(file_offset, sh_size_on_disk);
        let p_offset = if first_load {
            sh.sh_offset += extra_data;
            0
        } else {
            sh.sh_offset
        };
        let sh_size = sh.sh_size + extra_data;
        Some(ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | write | exec,
            p_align: PAGE_ALIGNMENT,
            p_offset,
            p_vaddr: *p_vaddr,
            p_paddr: post_inc(p_vaddr, sh_size),
            p_filesz: sh_size_on_disk,
            p_memsz: sh_size,
        })
    } else {
        None
    }
}

fn dyn_entries(names: &StringTable, sh: &SectionHeader) -> usize {
    let name = names.name(sh.sh_name as usize).unwrap();
    match name as &str {
        ".init" | ".fini" | ".got.plt" => 1,
        ".rela.dyn" => 4,
        ".rela.plt" => 3,
        _ => match sh.sh_type {
            SHT_DYNSYM | SHT_INIT_ARRAY | SHT_FINI_ARRAY => 2,
            SHT_STRTAB if sh.sh_flags & SHF_ALLOC as u64 == SHF_ALLOC as u64 => 2,
            SHT_HASH | SHT_GNU_HASH => 1,
            _ => 0,
        },
    }
}

fn try_add_dyn_entries(entries: &mut Vec<(DynTag, u64)>, names: &StringTable, sh: &SectionHeader) {
    let name = names.name(sh.sh_name as usize).unwrap();
    match name as &str {
        ".init" => entries.push((DynTag::Init, sh.sh_addr)),
        ".fini" => entries.push((DynTag::Fini, sh.sh_addr)),
        ".rela.dyn" => entries.extend(&[
            (DynTag::Rela, sh.sh_addr),
            (DynTag::RelaEnt, sh.sh_entsize),
            (DynTag::RelaSize, sh.sh_size),
            (DynTag::RelaCount, 0),
        ]),
        ".rela.plt" => entries.extend(&[
            (DynTag::JmpRel, sh.sh_addr),
            (DynTag::PltRel, DynTag::Rela as u64),
            (DynTag::PltRelSz, sh.sh_size),
        ]),
        ".got.plt" => entries.push((DynTag::PltGot, sh.sh_addr)),
        _ => match sh.sh_type {
            SHT_DYNSYM => {
                entries.extend(&[(DynTag::SymTab, sh.sh_addr), (DynTag::SymEnt, sh.sh_entsize)])
            }
            SHT_STRTAB if sh.sh_flags & SHF_ALLOC as u64 == SHF_ALLOC as u64 => {
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

fn p_type(names: &StringTable, sh: &SectionHeader) -> Option<u32> {
    match sh.sh_type {
        SHT_DYNAMIC => Some(PT_DYNAMIC),
        _ if names.name(sh.sh_name as usize).unwrap() as &str == ".interp" => Some(PT_INTERP),
        _ => None,
    }
}

fn post_inc(v: &mut u64, inc: u64) -> u64 {
    let tmp = *v;
    *v += inc;
    tmp
}

fn section_cmp(s1: &Section, s2: &Section) -> Ordering {
    match s1.sh_flags.cmp(&s2.sh_flags) {
        Ordering::Equal => s1.sh_addralign.cmp(&s2.sh_addralign).reverse(),
        // no flags should come last
        o => {
            if s1.sh_flags == 0 {
                Ordering::Greater
            } else if s2.sh_flags == 0 {
                Ordering::Less
            } else {
                o
            }
        }
    }
}

fn plt_entry_addr(base_addr: u64, index: usize) -> i64 {
    let addr = base_addr + PLT_ENTRY_SIZE as u64 * (1 + index as u64);
    addr.try_into().unwrap()
}
