#[derive(Debug)]
pub struct Symbol {
    is_weak: bool,
}

impl Symbol {
    pub const fn new(is_weak: bool) -> Self {
        Self { is_weak }
    }

    pub const fn is_weak(&self) -> bool {
        self.is_weak
    }
}
