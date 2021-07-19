use std::{fmt, io, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorType {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Elf(#[from] goblin::error::Error),
    #[error("Not an elf.")]
    NotAnElf,
    #[error("{0}")]
    Other(String),
}

impl From<String> for ErrorType {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

#[derive(Debug, Error)]
pub struct Error<'p> {
    path: &'p Path,
    ty: ErrorType,
}

impl<'p> Error<'p> {
    pub fn new(path: &'p Path, ty: impl Into<ErrorType>) -> Self {
        Error { path, ty: ty.into() }
    }
}

impl fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}`: {}", self.path.display(), self.ty)
    }
}

pub trait ErrorExt<T> {
    fn map_path_err<'p>(self, path: &'p Path) -> Result<T, Error<'p>>;
}

impl<T, E: Into<ErrorType>> ErrorExt<T> for Result<T, E> {
    fn map_path_err<'p>(self, path: &'p Path) -> Result<T, Error<'p>> {
        self.map_err(|e| Error::new(path, e))
    }
}
