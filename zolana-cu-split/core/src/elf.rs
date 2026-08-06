//! Program-counter to function-name resolution for an sBPF program.
//!
//! `cargo build-sbf` strips the deployed `.so` but leaves an unstripped build
//! with a byte-identical `.text` beside it. Symbols are read from the second
//! and applied to traces of the first; [`FunctionMap::from_paths`] refuses the
//! pair unless the two `.text` sections match, because a mismatch would
//! silently rename every frame.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

#[derive(Clone, Debug)]
pub struct FunctionSymbol {
    /// First program counter of the function, in sBPF instruction units.
    pub start_pc: u64,
    /// One past the last program counter.
    pub end_pc: u64,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct FunctionMap {
    symbols: Vec<FunctionSymbol>,
}

impl FunctionMap {
    /// Read symbols from `symbol_elf` after checking its `.text` equals the
    /// `.text` of `loaded_elf`.
    pub fn from_paths(loaded_elf: &Path, symbol_elf: &Path) -> Result<Self> {
        let loaded = std::fs::read(loaded_elf)
            .with_context(|| format!("read {}", loaded_elf.display()))?;
        let symbols = std::fs::read(symbol_elf)
            .with_context(|| format!("read {}", symbol_elf.display()))?;
        let loaded_text = text_section(&loaded)?;
        let symbol_text = text_section(&symbols)?;
        if loaded_text.1 != symbol_text.1 {
            bail!(
                "`.text` of {} and {} differ; symbols would misattribute",
                loaded_elf.display(),
                symbol_elf.display()
            );
        }
        Self::from_bytes(&symbols)
    }

    pub fn from_bytes(elf: &[u8]) -> Result<Self> {
        let file = object::File::parse(elf).context("parse sBPF ELF")?;
        let (text_addr, text) = text_section(elf)?;
        let text_end = text_addr + text.len() as u64;

        let mut symbols: Vec<FunctionSymbol> = file
            .symbols()
            .filter(|symbol| symbol.kind() == SymbolKind::Text)
            .filter(|symbol| symbol.address() >= text_addr && symbol.address() < text_end)
            .filter_map(|symbol| {
                let name = symbol.name().ok()?;
                let size = symbol.size();
                if size == 0 {
                    return None;
                }
                let start_pc = (symbol.address() - text_addr) / 8;
                let end_pc = (symbol.address() + size - text_addr).div_ceil(8);
                Some(FunctionSymbol {
                    start_pc,
                    end_pc,
                    name: rustc_demangle::demangle(name).to_string(),
                })
            })
            .collect();
        symbols.sort_by_key(|symbol| (symbol.start_pc, symbol.end_pc));
        if symbols.is_empty() {
            bail!("no sized text symbols; the ELF is stripped");
        }
        Ok(Self { symbols })
    }

    pub fn lookup(&self, pc: u64) -> Option<&FunctionSymbol> {
        let index = self
            .symbols
            .partition_point(|symbol| symbol.start_pc <= pc)
            .checked_sub(1)?;
        let symbol = &self.symbols[index];
        (pc < symbol.end_pc).then_some(symbol)
    }

    pub fn name(&self, pc: u64) -> String {
        self.lookup(pc)
            .map(|symbol| symbol.name.clone())
            .unwrap_or_else(|| format!("<unmapped pc {pc}>"))
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &FunctionSymbol> {
        self.symbols.iter()
    }
}

fn text_section(elf: &[u8]) -> Result<(u64, &[u8])> {
    let file = object::File::parse(elf).context("parse sBPF ELF")?;
    let section = file
        .section_by_name(".text")
        .ok_or_else(|| anyhow!("no .text section"))?;
    let addr = section.address();
    let data = section.data().context("read .text")?;
    // `object` borrows from the input slice, so tie the lifetime back to it.
    let range = section.file_range().ok_or_else(|| anyhow!("no .text range"))?;
    let start = range.0 as usize;
    let end = start + range.1 as usize;
    debug_assert_eq!(data.len(), end - start);
    Ok((addr, &elf[start..end]))
}
