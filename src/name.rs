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
