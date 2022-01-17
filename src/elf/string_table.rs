use goblin::elf64::section_header::{SectionHeader, SHT_STRTAB};

use crate::{name::Name, serialize::Serialize};

use std::collections::HashMap;

#[derive(Debug)]
pub struct Entry {
    pub index: usize,
    pub offset: usize,
    pub new: bool,
}

#[derive(Debug)]
pub struct StringTable {
    // name -> (index, offset)
    names: HashMap<Name, (usize, usize)>,
    total_len: usize,
}

impl Default for StringTable {
    fn default() -> Self {
        let mut table = Self { names: Default::default(), total_len: 0 };
        table.get_or_create("");
        table
    }
}

impl StringTable {
    pub fn with_name(name: impl Into<Name>) -> (Self, SectionHeader) {
        let mut table = Self::default();
        let entry = table.get_or_create(name);
        let sh = SectionHeader {
            sh_name: entry.offset as u32,
            sh_type: SHT_STRTAB,
            sh_addralign: 1,
            ..Default::default()
        };
        (table, sh)
    }

    pub fn new(sh_name: u32) -> (Self, SectionHeader) {
        let sh =
            SectionHeader { sh_name, sh_type: SHT_STRTAB, sh_addralign: 1, ..Default::default() };
        (Self::default(), sh)
    }

    pub fn get_or_create(&mut self, name: impl Into<Name>) -> Entry {
        let mut new = false;
        let mut add_len = 0;
        let name = name.into();
        let name_len = name.len();
        let v = self.total_len;
        let len = self.names.len();
        let (i, offset) = self.names.entry(name).or_insert_with(|| {
            add_len = name_len + 1;
            new = true;
            (len, v)
        });
        self.total_len += add_len;
        Entry { index: *i, offset: *offset, new }
    }

    pub fn get(&self, name: impl Into<Name>) -> Option<Entry> {
        let name = name.into();
        self.names.get(&name).map(|(i, o)| Entry { index: *i, offset: *o, new: false })
    }

    pub fn sh_name(&self, name: impl Into<Name>) -> u32 {
        self.names.get(&name.into()).unwrap().1 as u32
    }

    pub fn name(&self, offset: usize) -> Option<&Name> {
        self.names.iter().find(|(_, v)| v.1 == offset).map(|(k, _)| k)
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn sorted_names(&self) -> Vec<(Name, (usize, usize))> {
        let mut names = self
            .names
            .iter()
            // wish I could use `.cloned`
            .map(|v| (v.0.clone(), (v.1 .0, v.1 .1)))
            .collect::<Vec<(_, (usize, usize))>>();
        names.sort_by(|a, b| a.1 .1.cmp(&b.1 .1));
        names
    }

    pub fn chunk(&self) -> crate::elf::Chunk {
        let mut data = Vec::with_capacity(self.total_len);
        let names = self.sorted_names();
        for (name, _) in names {
            name.serialize(&mut data);
        }
        data.into()
    }
}
