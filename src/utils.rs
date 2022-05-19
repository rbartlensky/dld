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

pub fn is_some_with<T>(opt: Option<T>, v: &T) -> bool
where
    T: std::cmp::PartialEq,
{
    match opt {
        Some(inner) if &inner == v => true,
        _ => false,
    }
}
