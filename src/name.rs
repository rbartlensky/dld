use std::{
    hash::{Hash, Hasher},
    ops::Deref,
};

#[derive(Clone, Debug, Eq)]
pub enum Name {
    String(String),
    Static(&'static str),
}

impl From<String> for Name {
    fn from(name: String) -> Self {
        Self::String(name)
    }
}

impl From<&'static str> for Name {
    fn from(name: &'static str) -> Self {
        Self::Static(name)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Name::String(s) => s.as_str(),
            Name::Static(s) => s,
        }
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state);
    }
}

impl Name {
    // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html
    pub fn elf_hash(&self) -> u32 {
        let mut h = 0;
        let mut g;
        for b in (self as &str).as_bytes() {
            h = (h << 4) + (*b as u32);
            g = h & 0xf0000000;
            if g != 0 {
                h ^= g >> 24;
            }
            h &= !g;
        }
        h
    }
}
