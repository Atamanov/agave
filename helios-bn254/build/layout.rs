//! Typed layouts for kernel spill frames and rodata walk tables.
//!
//! A frame is a sequence of named slots with cursor-assigned offsets, so a
//! slot can never silently move or overlap; deliberate sharing is declared
//! ([`FrameLayout::alias`] re-walks another kernel's slot at the same
//! offset, [`FrameLayout::union_at`] carves a view out of an existing slot).
//! A rodata walk table is a sequence of segments with an explicit row shape,
//! and the table builders assert their blobs against those boundaries. All
//! construction is `const`, so a mistake is a compile error; the emitted
//! displacement bytes are pinned by the golden text on top.

use super::machine::{Mem, Reg};

/// A named byte range in a kernel's rsp-relative spill frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameSlot {
    off: i32,
    size: i32,
}

impl FrameSlot {
    /// Frame byte offset of the slot's first byte.
    pub const fn off(self) -> i32 {
        self.off
    }

    /// `[rsp + off + delta]`, bounds-checked against the slot.
    pub const fn at(self, delta: i32) -> Mem {
        assert!(0 <= delta && delta < self.size, "slot access out of range");
        Mem::new(Reg::Rsp, self.off + delta)
    }

    pub const fn mem(self) -> Mem {
        self.at(0)
    }

    /// 8-byte word `k` of the slot.
    pub const fn limb(self, k: usize) -> Mem {
        self.at(8 * k as i32)
    }

    /// Whether `inner` lies entirely inside this slot (declared overlaps).
    pub const fn contains(self, inner: FrameSlot) -> bool {
        self.off <= inner.off && inner.off + inner.size <= self.off + self.size
    }
}

/// Sequential frame-layout builder: every byte of the frame is claimed by
/// exactly one `slot`, `alias`, or `gap`, in offset order.
#[derive(Clone, Copy)]
pub struct FrameLayout {
    cursor: i32,
}

impl FrameLayout {
    pub const fn new() -> Self {
        FrameLayout { cursor: 0 }
    }

    /// Claim `size` bytes at the cursor.
    pub const fn slot(mut self, size: i32) -> (Self, FrameSlot) {
        assert!(size > 0 && size % 8 == 0, "slot is a positive 8-multiple");
        let slot = FrameSlot {
            off: self.cursor,
            size,
        };
        self.cursor += size;
        (self, slot)
    }

    /// Walk over a slot declared by another layout: the deliberate
    /// cross-kernel sharing is checked (the slot must sit exactly at the
    /// cursor) instead of relying on hand-matched constants.
    pub const fn alias(mut self, shared: FrameSlot) -> Self {
        assert!(
            shared.off == self.cursor,
            "aliased slot is not at the cursor"
        );
        self.cursor += shared.size;
        self
    }

    /// Skip deliberately unused bytes.
    pub const fn gap(mut self, bytes: i32) -> Self {
        assert!(bytes > 0 && bytes % 8 == 0, "gap is a positive 8-multiple");
        self.cursor += bytes;
        self
    }

    /// A view sharing `outer`'s storage at `delta` bytes in (deliberate
    /// overlap; the cursor does not move).
    #[cfg(test)]
    pub const fn union_at(self, outer: FrameSlot, delta: i32, size: i32) -> FrameSlot {
        assert!(
            0 <= delta && delta + size <= outer.size,
            "union view leaves its outer slot"
        );
        FrameSlot {
            off: outer.off + delta,
            size,
        }
    }

    /// Total frame size: the `alloc_stack` operand.
    pub const fn size(self) -> i32 {
        assert!(self.cursor > 0 && self.cursor % 8 == 0);
        self.cursor
    }
}

impl Default for FrameLayout {
    fn default() -> Self {
        Self::new()
    }
}

/// One region of a rodata walk table: `rows` rows of `row_u64s` fields.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TableSegment {
    off: i32,
    row_bytes: i32,
    rows: i32,
}

impl TableSegment {
    /// Byte offset of the segment inside the blob.
    pub const fn off(self) -> i32 {
        self.off
    }

    /// Row stride in bytes (the walk cursor's step).
    pub const fn row_bytes(self) -> i32 {
        self.row_bytes
    }

    pub const fn bytes(self) -> i32 {
        self.row_bytes * self.rows
    }

    /// Byte offset of row `i`; `i == rows` addresses the segment end.
    pub const fn row(self, i: i32) -> i32 {
        assert!(0 <= i && i <= self.rows, "row index out of range");
        self.off + i * self.row_bytes
    }

    pub const fn end(self) -> i32 {
        self.off + self.bytes()
    }
}

/// Sequential rodata-table builder: segments are contiguous in blob order.
#[derive(Clone, Copy)]
pub struct TableLayout {
    cursor: i32,
}

impl TableLayout {
    pub const fn new() -> Self {
        TableLayout { cursor: 0 }
    }

    /// Declare `rows` rows of `row_u64s` u64 fields at the cursor.
    pub const fn seg(mut self, rows: i32, row_u64s: i32) -> (Self, TableSegment) {
        assert!(rows > 0 && row_u64s > 0);
        let seg = TableSegment {
            off: self.cursor,
            row_bytes: 8 * row_u64s,
            rows,
        };
        self.cursor += seg.bytes();
        (self, seg)
    }

    /// Total table size in bytes.
    pub const fn bytes(self) -> i32 {
        self.cursor
    }
}

impl Default for TableLayout {
    fn default() -> Self {
        Self::new()
    }
}
