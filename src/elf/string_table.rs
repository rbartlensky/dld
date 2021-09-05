use crate::name::Name;

use std::collections::HashMap;

pub struct Entry {
    pub index: usize,
    pub offset: usize,
    pub new: bool,
}

#[derive(Default)]
pub struct StringTable {
    // name -> (index, offset)
    names: HashMap<Name, (usize, usize)>,
    total_len: usize,
}

impl StringTable {
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

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn sorted_names(&self) -> Vec<(Name, (usize, usize))> {
        let mut names = self
            .names
            .iter()
            // wish I could use `.cloned`
            .map(|v| (v.0.clone(), (v.1.0, v.1.1)))
            .collect::<Vec<(_, (usize, usize))>>();
        names.sort_by(|a, b| a.1 .1.cmp(&b.1 .1));
        names
    }
}
