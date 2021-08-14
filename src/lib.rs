pub mod error;
mod elf;
mod name;
mod object;
mod symbol;
mod serialize;

use error::{Error, ErrorExt, ErrorType};
use object::Object;
use std::{
    fs::read,
    path::{Path, PathBuf},
};

pub fn link<'p>(inputs: &'p [PathBuf], output: &'p Path) -> Result<(), Error<'p>> {
    let mut text: Vec<u8> = vec![];
    let mut writer = elf::Writer::new(output).map_path_err(output)?;
    for input in inputs.iter().map(|p| p.as_path()) {
        let buf = read(input).map_path_err(input)?;
        let obj = goblin::Object::parse(&buf).map_path_err(input)?;
        if let goblin::Object::Elf(elf) = obj {
            let object = Object::new(elf, &buf);
            text.extend(object.text_section());
            for symbol in object.symbols() {
                let name = object.get_name(symbol.st_name).map_path_err(input)?;
                writer
                    .add_symbol(symbol.into(), name, input)
                    .map_path_err(input)?;
            }
        } else {
            return Err(Error::new(input, ErrorType::NotAnElf));
        }
    }
    writer.add_text(&text);
    writer.write_to_disk();

    Ok(())
}
