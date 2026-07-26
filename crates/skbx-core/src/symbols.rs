use std::fs;

#[derive(Clone, Debug, Default)]
pub struct SymbolTable {
    entries: Vec<(u64, String)>,
}

impl SymbolTable {
    pub fn from_kallsyms() -> Self {
        fs::read_to_string("/proc/kallsyms")
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    pub fn parse(text: &str) -> Self {
        let mut entries: Vec<(u64, String)> = text
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let address = u64::from_str_radix(fields.next()?, 16).ok()?;
                let _kind = fields.next()?;
                let name = fields.next()?.to_owned();
                (address != 0).then_some((address, name))
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        Self { entries }
    }

    pub fn resolve(&self, address: u64) -> Option<&str> {
        let index = self
            .entries
            .partition_point(|(candidate, _)| *candidate <= address);
        index
            .checked_sub(1)
            .and_then(|index| self.entries.get(index))
            .map(|(_, name)| name.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_nearest_symbol_without_using_zero_addresses() {
        let symbols = SymbolTable::parse(
            "0000000000000000 T hidden\n0000000000001000 T first\n0000000000001100 T second\n",
        );
        assert_eq!(symbols.resolve(0x10ff), Some("first"));
        assert_eq!(symbols.resolve(0x1100), Some("second"));
        assert_eq!(symbols.resolve(0x0fff), None);
    }
}
