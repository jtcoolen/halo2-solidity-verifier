//! Small codegen-only newtypes for byte/word units and proof encodings.
//!
//! The existing generator still uses raw `usize`/byte slices in many places.
//! These wrappers give new planning code a typed vocabulary without changing
//! the public rendering APIs or forcing a large migration in one patch.

#![allow(dead_code)]

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct ByteOffset(pub(crate) usize);

impl ByteOffset {
    pub(crate) const fn new(value: usize) -> Self {
        Self(value)
    }

    pub(crate) const fn as_usize(self) -> usize {
        self.0
    }

    pub(crate) const fn from_words(words: WordOffset) -> Self {
        Self(words.0 * crate::codegen::layout::WORD_BYTES)
    }

    pub(crate) fn checked_add_bytes(self, bytes: usize) -> Option<Self> {
        self.0.checked_add(bytes).map(Self)
    }

    pub(crate) fn to_word_offset(self) -> Option<WordOffset> {
        (self.0 % crate::codegen::layout::WORD_BYTES == 0)
            .then_some(WordOffset(self.0 / crate::codegen::layout::WORD_BYTES))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct WordOffset(pub(crate) usize);

impl WordOffset {
    pub(crate) const fn new(value: usize) -> Self {
        Self(value)
    }

    pub(crate) const fn as_usize(self) -> usize {
        self.0
    }

    pub(crate) const fn to_byte_offset(self) -> ByteOffset {
        ByteOffset::from_words(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MemoryPtr(pub(crate) ByteOffset);

impl MemoryPtr {
    pub(crate) const fn new(byte_offset: ByteOffset) -> Self {
        Self(byte_offset)
    }

    pub(crate) const fn byte_offset(self) -> ByteOffset {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct CalldataPtr(pub(crate) ByteOffset);

impl CalldataPtr {
    pub(crate) const fn new(byte_offset: ByteOffset) -> Self {
        Self(byte_offset)
    }

    pub(crate) const fn byte_offset(self) -> ByteOffset {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct OriginalColumn(pub(crate) usize);

impl OriginalColumn {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct PhaseSortedColumn(pub(crate) usize);

impl PhaseSortedColumn {
    pub(crate) const fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct FrLeBytes(pub(crate) [u8; 32]);

impl FrLeBytes {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct FrBeWord(pub(crate) [u8; 32]);

impl FrBeWord {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct G1Compressed(pub(crate) [u8; crate::codegen::layout::G1_COMPRESSED_BYTES]);

impl G1Compressed {
    pub(crate) const fn new(bytes: [u8; crate::codegen::layout::G1_COMPRESSED_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(self) -> [u8; crate::codegen::layout::G1_COMPRESSED_BYTES] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct G1Eip2537(pub(crate) [u8; crate::codegen::layout::G1_BYTES]);

impl G1Eip2537 {
    pub(crate) const fn new(bytes: [u8; crate::codegen::layout::G1_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(self) -> [u8; crate::codegen::layout::G1_BYTES] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_and_word_offsets_are_explicit() {
        let words = WordOffset::new(7);
        let bytes = words.to_byte_offset();
        assert_eq!(bytes.as_usize(), 7 * crate::codegen::layout::WORD_BYTES);
        assert_eq!(bytes.to_word_offset(), Some(words));
        assert_eq!(ByteOffset::new(7).to_word_offset(), None);
    }

    #[test]
    fn original_and_phase_sorted_columns_do_not_alias_by_type() {
        let original = OriginalColumn::new(2);
        let phase_sorted = PhaseSortedColumn::new(2);
        assert_eq!(original.index(), phase_sorted.index());
    }
}
