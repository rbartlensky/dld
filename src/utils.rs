// I find a function more readable in this case
pub fn is_some_with<T>(opt: Option<T>, v: &T) -> bool
where
    T: std::cmp::PartialEq,
{
    matches!(opt, Some(inner) if &inner == v)
}
