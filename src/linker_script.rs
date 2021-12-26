use combine::error::{ParseError, StringStreamError};
use combine::parser::char::{alpha_num, char, space, string};
use combine::parser::repeat::skip_until;
use combine::stream::Stream;
use combine::{between, choice, many1, optional, sep_end_by, skip_many, skip_many1, Parser};

/// Parses an argument like: 'foo.so' or `/lib/foo.so'.
pub fn parse_arg<Input>() -> impl Parser<Input, Output = String>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    many1(choice((alpha_num(), char('-'), char('.'), char('_'), char('/'))))
}
/// Parses a comment like: /* hey \n second line */
pub fn parse_comment<Input>() -> impl Parser<Input, Output = ()>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    between(string("/*"), string("*/"), skip_until(string("*/")))
}

/// Parses a GROUP command like: GROUP ( libgcc_s.so.1 -lgcc )
pub fn parse_group_command<Input>() -> impl Parser<Input, Output = Vec<String>>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    let args = (
        skip_many(space()),
        sep_end_by(parse_as_needed_command().or(parse_arg().map(|v| vec![v])), skip_many(space())),
    );
    (string("GROUP"), skip_many(space()), between(char('('), char(')'), args))
        .map(|(_, _, s): (_, _, ((), Vec<Vec<String>>))| s.1.into_iter().flatten().collect())
}

/// Parses an AS_NEEDED block like: AS_NEEDED ( foo.so )
pub fn parse_as_needed_command<Input>() -> impl Parser<Input, Output = Vec<String>>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    let args = (skip_many(space()), sep_end_by(parse_arg(), skip_many(space())));
    (string("AS_NEEDED"), skip_many(space()), between(char('('), char(')'), args)).map(
        |(_, _, s): (_, _, (_, Vec<String>))| {
            let mut v: Vec<String> = vec!["--as-needed".into()];
            v.extend(s.1);
            v
        },
    )
}

/// Parses a OUTPUT_FORMAT command like: OUTPUT_FORMAT(elf64-x86-64)
pub fn parse_output_format_command<Input>() -> impl Parser<Input, Output = Vec<String>>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    let args = (skip_many(space()), parse_arg(), skip_many(space()));
    (string("OUTPUT_FORMAT"), skip_many(space()), between(char('('), char(')'), args))
        // TODO: handle output format argument
        .map(|(_, _, _): (_, _, (_, String, _))| vec![])
}

pub fn parse(mut input: &str) -> Result<Vec<String>, StringStreamError> {
    let mut new_args = vec![];
    let skip_ws_and_comments =
        skip_many(skip_many1(space()).or(parse_comment()).or(char('\n').map(|_| ())));
    let mut line = (
        skip_ws_and_comments,
        optional(choice((parse_group_command(), parse_output_format_command()))),
    );
    loop {
        let ((_, args), leftover) = line.parse(input)?;
        if let Some(args) = args {
            new_args.extend(args);
        }
        if !leftover.is_empty() {
            input = leftover;
        } else {
            break;
        }
    }
    Ok(new_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_block() {
        let s = r"GROUP ( libgcc_s.so.1 -lgcc )";
        assert_eq!(parse(s), Ok(vec!["libgcc_s.so.1".into(), "-lgcc".into()]));
    }

    #[test]
    fn group_as_needed_block() {
        let s = r"GROUP ( libgcc_s.so.1 /lib/lib.so AS_NEEDED( -lgcc ) libgcc_2.so )";
        assert_eq!(
            parse(s),
            Ok(vec![
                "libgcc_s.so.1".into(),
                "/lib/lib.so".into(),
                "--as-needed".into(),
                "-lgcc".into(),
                "libgcc_2.so".into()
            ])
        );
    }

    #[test]
    fn output_format() {
        let s = r"OUTPUT_FORMAT(elf64-x86-64)";
        assert_eq!(parse(s), Ok(vec![]));
    }

    #[test]
    fn as_neeed() {
        let s = r"AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 )";
        assert_eq!(
            parse_as_needed_command().parse(s).map(|v| v.0),
            Ok(vec!["--as-needed".into(), "/lib64/ld-linux-x86-64.so.2".into()])
        );
    }

    #[test]
    fn libc() {
        let s = r"/* GNU ld script
   Use the shared library, but some functions are only in
   the static library, so try that secondarily.  */
OUTPUT_FORMAT(elf64-x86-64)
GROUP ( /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc_nonshared.a  AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 ) )
";
        assert_eq!(
            parse(s),
            Ok(vec![
                "/lib/x86_64-linux-gnu/libc.so.6".into(),
                "/usr/lib/x86_64-linux-gnu/libc_nonshared.a".into(),
                "--as-needed".into(),
                "/lib64/ld-linux-x86-64.so.2".into()
            ])
        );
    }
}
