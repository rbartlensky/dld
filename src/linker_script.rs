use combine::error::{ParseError, StringStreamError};
use combine::parser::char::{alpha_num, char, space, string};
use combine::parser::repeat::skip_until;
use combine::stream::Stream;
use combine::{between, choice, many1, sep_end_by, skip_many, skip_many1, Parser};

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
    let arg = choice((alpha_num(), char('-'), char('.'), char('_')));
    let args = (skip_many(space()), sep_end_by(many1(arg), skip_many1(space())));

    (string("GROUP"), skip_many(space()), between(char('('), char(')'), args)).map(|(_, _, s)| s.1)
}

pub fn parse(input: &str) -> Result<Vec<String>, StringStreamError> {
    let skip_ws_and_comments = skip_many(skip_many1(space()).or(parse_comment()));
    (skip_ws_and_comments, parse_group_command()).parse(input).map(|r| r.0 .1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_block() {
        let s = r"GROUP ( libgcc_s.so.1 -lgcc )";
        assert_eq!(parse(s), Ok(vec!["libgcc_s.so.1".into(), "-lgcc".into()]));
    }
}
