pub fn map_if_eq<T, U, F>(opt: Option<T>, v: &T, f: F) -> Option<U>
where
    T: std::cmp::PartialEq,
    F: FnOnce(T) -> U,
{
    match opt {
        Some(inner) if &inner == v => Some(f(inner)),
        _ => None,
    }
}

// I find a function more readable in this case
pub fn is_some_with<T>(opt: Option<T>, v: &T) -> bool
where
    T: std::cmp::PartialEq,
{
    matches!(opt, Some(inner) if &inner == v)
}
