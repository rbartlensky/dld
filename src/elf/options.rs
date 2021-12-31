use std::{path::PathBuf, str::FromStr};

#[derive(Debug)]
pub enum BuildId {
    UUID,
    SHA1,
    MD5,
    Hex(String),
}

impl FromStr for BuildId {
    type Err = &'static str;

    fn from_str(bid: &str) -> Result<Self, Self::Err> {
        match bid {
            "uuid" => Ok(BuildId::UUID),
            "sha1" => Ok(BuildId::SHA1),
            "md5" => Ok(BuildId::MD5),
            bid if bid.starts_with("0x") => Ok(BuildId::Hex(bid[2..].into())),
            _ => Err(
                "invalid build id style, only 'uuid', 'sha1', 'md1', or '0x<hexstring>' allowed",
            ),
        }
    }
}

impl Default for BuildId {
    fn default() -> Self {
        BuildId::SHA1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStyle {
    Sysv,
    Gnu,
    Both,
}

impl FromStr for HashStyle {
    type Err = &'static str;

    fn from_str(style: &str) -> Result<Self, Self::Err> {
        match style {
            "sysv" => Ok(HashStyle::Sysv),
            "gnu" => Ok(HashStyle::Gnu),
            "both" => Ok(HashStyle::Both),
            _ => Err("invalid hash style, only 'gnu', 'sysv', or 'both' allowed"),
        }
    }
}

impl Default for HashStyle {
    fn default() -> Self {
        HashStyle::Both
    }
}

#[derive(Debug)]
pub enum Emulation {
    ElfX86_64,
}

impl FromStr for Emulation {
    type Err = &'static str;

    fn from_str(style: &str) -> Result<Self, Self::Err> {
        match style {
            "elf_x86_64" => Ok(Emulation::ElfX86_64),
            _ => Err("invalid emulation, only 'elf_x86_64' supported"),
        }
    }
}

impl Default for Emulation {
    fn default() -> Self {
        Emulation::ElfX86_64
    }
}

#[derive(Debug)]
pub struct Options {
    pub output: PathBuf,
    // TODO:
    pub build_id: Option<BuildId>,
    pub hash_style: HashStyle,
    pub eh_frame_hdr: bool,
    pub emulation: Emulation,
    pub dynamic_linker: PathBuf,
    pub shared_libs: Vec<(PathBuf, bool)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            output: PathBuf::from("./out"),
            build_id: None,
            hash_style: Default::default(),
            eh_frame_hdr: false,
            emulation: Default::default(),
            dynamic_linker: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            shared_libs: vec![],
        }
    }
}
