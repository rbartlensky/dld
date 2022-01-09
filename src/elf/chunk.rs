use byteorder::{LittleEndian, WriteBytesExt};
use goblin::elf64::header::EM_X86_64;
use goblin::elf64::reloc::{Rela, *};
use std::{convert::TryInto, io::Write};

use crate::elf::{SymbolRef, SymbolTable};

/// A part of a section.
pub struct Chunk {
    data: Vec<u8>,
    symbols: Vec<SymbolRef>,
    relocations: Vec<(Rela, SymbolRef)>,
}

impl Chunk {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, symbols: vec![], relocations: vec![] }
    }

    pub fn add_symbol(&mut self, sym_ref: SymbolRef) {
        self.symbols.push(sym_ref);
    }

    pub fn add_relocation(&mut self, reloc: Rela, sym_ref: SymbolRef) {
        self.relocations.push((reloc, sym_ref));
    }

    pub fn symbols(&self) -> &[SymbolRef] {
        &self.symbols[..]
    }

    pub fn apply_relocations(&mut self, got_address: u64, plt_address: u64, table: &SymbolTable) {
        for (rela, symbol_ref) in &self.relocations {
            apply_relocation(
                &mut self.data[..],
                *rela,
                table.get(*symbol_ref).unwrap(),
                got_address,
                plt_address,
            );
        }
    }
}

impl From<Vec<u8>> for Chunk {
    fn from(other: Vec<u8>) -> Self {
        Self::new(other)
    }
}

impl std::ops::Deref for Chunk {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for Chunk {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

fn apply_relocation(
    data: &mut [u8],
    rel: Rela,
    symbol: &crate::elf::Symbol<'_>,
    got_address: u64,
    plt_address: u64,
) {
    let is_symbol_local = symbol.is_local();
    let s: i64 = symbol.st_value.try_into().unwrap();
    let a = rel.r_addend;
    let p: i64 = rel.r_offset.try_into().unwrap();
    let _z = symbol.st_size;
    let got: i64 = got_address.try_into().unwrap();
    let l: i64 = plt_address.try_into().unwrap();
    let offset = rel.r_offset as usize;
    match (rel.r_info & 0xffff_ffff) as u32 {
        R_X86_64_NONE => {}
        R_X86_64_64 => (&mut data[offset..]).write_i64::<LittleEndian>(s + a).unwrap(),
        R_X86_64_32 => {
            (&mut data[offset..]).write_i32::<LittleEndian>((s + a).try_into().unwrap()).unwrap()
        }
        R_X86_64_32S => {
            // TODO warn about truncation
            (&mut data[offset..]).write_i32::<LittleEndian>((s + a) as i32).unwrap()
        }
        R_X86_64_PC32 => (&mut data[offset..])
            .write_i32::<LittleEndian>((s + a - p).try_into().unwrap())
            .unwrap(),
        R_X86_64_GOT32 => {
            let g: i64 = symbol.got_offset().unwrap().try_into().unwrap();
            (&mut data[offset..]).write_i32::<LittleEndian>((g + a).try_into().unwrap()).unwrap()
        }
        R_X86_64_GOTPCRELX if is_symbol_local => {
            // -2 because the offset points to where we need to patch, but we want to
            // match the other two bytes to tell which instruction we're patching
            let buf = &mut data[offset - 2..];
            let value: i32 = (s + a - p).try_into().unwrap();
            match buf[..2] {
                // call *foo@GOTPCREL(%rip) -> call foo nop
                [0xff, 0x15] => {
                    buf[0] = 0xe8;
                    buf[1..5].as_mut().write_i32::<LittleEndian>(value).unwrap();
                    buf[5] = 0x90;
                }
                // jmp *foo@GOTPCREL(%rip) -> jmp foo nop
                [0xff, 0x25] => {
                    buf[0] = 0xe9;
                    buf[1..5].as_mut().write_i32::<LittleEndian>(value).unwrap();
                    buf[5] = 0x90;
                }
                ref x => unreachable!("{:?}", x),
            }
        }
        R_X86_64_GOTPCRELX => {
            let g: i64 = symbol.got_offset().unwrap().try_into().unwrap();
            let value: i32 = (g + got + a - p).try_into().unwrap();
            (&mut data[offset..]).write_i32::<LittleEndian>(value).unwrap();
        }
        R_X86_64_REX_GOTPCRELX => {
            if is_symbol_local {
                let buf = &mut data[offset - 3..];
                let instr = match buf[..3] {
                    [0x48, 0x8b, 0x05] => [0x48, 0xc7, 0xc0], // mov 0x0(%rip),%rax -> mov $0x0,%rax
                    [0x48, 0x8b, 0x1d] => [0x48, 0xc7, 0xc3], // mov 0x0(%rip),%rbx -> mov $0x0,%rbx
                    [0x48, 0x8b, 0x0d] => [0x48, 0xc7, 0xc1], // mov 0x0(%rip),%rcx -> mov $0x0,%rcx
                    [0x48, 0x8b, 0x15] => [0x48, 0xc7, 0xc2], // mov 0x0(%rip),%rdx -> mov $0x0,%rdx
                    [0x48, 0x8b, 0x35] => [0x48, 0xc7, 0xc6], // mov 0x0(%rip),%rsi -> mov $0x0,%rsi
                    [0x48, 0x8b, 0x3d] => [0x48, 0xc7, 0xc7], // mov 0x0(%rip),%rdi -> mov $0x0,%rdi
                    [0x48, 0x8b, 0x25] => [0x48, 0xc7, 0xc4], // mov 0x0(%rip),%rsp -> mov $0x0,%rsp
                    [0x48, 0x8b, 0x2d] => [0x48, 0xc7, 0xc5], // mov 0x0(%rip),%rbp -> mov $0x0,%rbp
                    [0x4c, 0x8b, 0x05] => [0x49, 0xc7, 0xc0], // mov 0x0(%rip),%r8 -> mov $0x0,%r8
                    [0x4c, 0x8b, 0x0d] => [0x49, 0xc7, 0xc1], // mov 0x0(%rip),%r9 -> mov $0x0,%r9
                    [0x4c, 0x8b, 0x15] => [0x49, 0xc7, 0xc2], // mov 0x0(%rip),%r10 -> mov $0x0,%r10
                    [0x4c, 0x8b, 0x1d] => [0x49, 0xc7, 0xc3], // mov 0x0(%rip),%r11 -> mov $0x0,%r11
                    [0x4c, 0x8b, 0x25] => [0x49, 0xc7, 0xc4], // mov 0x0(%rip),%r12 -> mov $0x0,%r12
                    [0x4c, 0x8b, 0x2d] => [0x49, 0xc7, 0xc5], // mov 0x0(%rip),%r13 -> mov $0x0,%r13
                    [0x4c, 0x8b, 0x35] => [0x49, 0xc7, 0xc6], // mov 0x0(%rip),%r14 -> mov $0x0,%r14
                    [0x4c, 0x8b, 0x3d] => [0x49, 0xc7, 0xc7], // mov 0x0(%rip),%r15 -> mov $0x0,%r15
                    ref x => unreachable!("{:?}", &x),
                };
                buf[..3].as_mut().write_all(&instr).unwrap();
                let value: i32 = (s + a - p).try_into().unwrap();
                buf[3..].as_mut().write_i32::<LittleEndian>(value).unwrap();
            } else {
                let g: i64 = symbol.got_offset().unwrap().try_into().unwrap();
                let value: i32 = (g + got + a - p).try_into().unwrap();
                let buf = &mut data[offset..];
                buf[3..].as_mut().write_i32::<LittleEndian>(value).unwrap();
            };
        }
        R_X86_64_TLSGD => {
            assert!(symbol.is_tls());
            let got_offset = symbol.got_offset().unwrap();
            let value = got_offset as i64 + got + a - p;
            (&mut data[offset..]).write_i32::<LittleEndian>(value.try_into().unwrap()).unwrap();
        }
        R_X86_64_GOTTPOFF => {
            assert!(symbol.is_tls());
            let got_offset = symbol.got_offset().unwrap();
            let value = got_offset as i64 + got + a - p;
            (&mut data[offset..]).write_i32::<LittleEndian>(value.try_into().unwrap()).unwrap();
        }
        R_X86_64_TPOFF32 => {
            let value = s + a;
            (&mut data[offset..]).write_i32::<LittleEndian>(value.try_into().unwrap()).unwrap();
        }
        R_X86_64_PLT32 => {
            let value = l + a - p;
            (&mut data[offset..]).write_i32::<LittleEndian>(value.try_into().unwrap()).unwrap();
        }
        x => unimplemented!("Relocation {}", r_to_str(x, EM_X86_64)),
    }
}
