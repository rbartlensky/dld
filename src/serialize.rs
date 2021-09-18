use byteorder::{LittleEndian, WriteBytesExt};
use goblin::elf64::{
    header::Header, program_header::ProgramHeader, section_header::SectionHeader, sym::Sym,
};

use std::{io::Write, mem::size_of};

pub trait Serialize<W: Write> {
    fn serialize(&self, buf: &mut W) -> usize;
}

impl<W: Write> Serialize<W> for Header {
    fn serialize(&self, buf: &mut W) -> usize {
        buf.write_all(&self.e_ident).unwrap();
        buf.write_u16::<LittleEndian>(self.e_type).unwrap();
        buf.write_u16::<LittleEndian>(self.e_machine).unwrap();
        buf.write_u32::<LittleEndian>(self.e_version).unwrap();
        buf.write_u64::<LittleEndian>(self.e_entry).unwrap();
        buf.write_u64::<LittleEndian>(self.e_phoff).unwrap();
        buf.write_u64::<LittleEndian>(self.e_shoff).unwrap();
        buf.write_u32::<LittleEndian>(self.e_flags).unwrap();
        buf.write_u16::<LittleEndian>(self.e_ehsize).unwrap();
        buf.write_u16::<LittleEndian>(self.e_phentsize).unwrap();
        buf.write_u16::<LittleEndian>(self.e_phnum).unwrap();
        buf.write_u16::<LittleEndian>(self.e_shentsize).unwrap();
        buf.write_u16::<LittleEndian>(self.e_shnum).unwrap();
        buf.write_u16::<LittleEndian>(self.e_shstrndx).unwrap();
        size_of::<Header>()
    }
}

impl<W: Write> Serialize<W> for ProgramHeader {
    fn serialize(&self, buf: &mut W) -> usize {
        buf.write_u32::<LittleEndian>(self.p_type).unwrap();
        buf.write_u32::<LittleEndian>(self.p_flags).unwrap();
        buf.write_u64::<LittleEndian>(self.p_offset).unwrap();
        buf.write_u64::<LittleEndian>(self.p_vaddr).unwrap();
        buf.write_u64::<LittleEndian>(self.p_paddr).unwrap();
        buf.write_u64::<LittleEndian>(self.p_filesz).unwrap();
        buf.write_u64::<LittleEndian>(self.p_memsz).unwrap();
        buf.write_u64::<LittleEndian>(self.p_align).unwrap();
        size_of::<ProgramHeader>()
    }
}

impl<W: Write> Serialize<W> for SectionHeader {
    fn serialize(&self, buf: &mut W) -> usize {
        buf.write_u32::<LittleEndian>(self.sh_name as u32).unwrap();
        buf.write_u32::<LittleEndian>(self.sh_type).unwrap();
        buf.write_u64::<LittleEndian>(self.sh_flags).unwrap();
        buf.write_u64::<LittleEndian>(self.sh_addr).unwrap();
        buf.write_u64::<LittleEndian>(self.sh_offset).unwrap();
        buf.write_u64::<LittleEndian>(self.sh_size).unwrap();
        buf.write_u32::<LittleEndian>(self.sh_link).unwrap();
        buf.write_u32::<LittleEndian>(self.sh_info).unwrap();
        buf.write_u64::<LittleEndian>(self.sh_addralign).unwrap();
        buf.write_u64::<LittleEndian>(self.sh_entsize).unwrap();
        // `sh_name` is a usize, but we always encode it as a u32
        size_of::<SectionHeader>() - (size_of::<usize>() - size_of::<u32>())
    }
}

impl<W: Write> Serialize<W> for Sym {
    fn serialize(&self, buf: &mut W) -> usize {
        buf.write_u32::<LittleEndian>(self.st_name).unwrap();
        buf.write_u8(self.st_info).unwrap();
        buf.write_u8(self.st_other).unwrap();
        buf.write_u16::<LittleEndian>(self.st_shndx).unwrap();
        buf.write_u64::<LittleEndian>(self.st_value).unwrap();
        buf.write_u64::<LittleEndian>(self.st_size).unwrap();
        size_of::<Sym>()
    }
}
