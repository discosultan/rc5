use core::cmp::max;

use crate::{
    bytes::ByteIntegerExt,
    consts::{p, q},
};

/// Provides the RC5 encryption algorithm.
///
/// See <https://www.grc.com/r&d/rc5.pdf> for more info.
///
/// Example usage:
/// ```
/// use rc5::RC5;
///
/// let key = [0x00, 0x01, 0x02, 0x03];
/// let plaintext = [0x00, 0x01];
/// let ciphertext = [0x21, 0x2A];
///
/// // RC5-8/12/4
/// let rc5 = RC5::<8, 12, 4, 1, 2, 26, 4>::new(key);
///
/// assert_eq!(rc5.encrypt(plaintext), ciphertext);
/// assert_eq!(rc5.decrypt(ciphertext), plaintext);
/// ```
pub struct RC5<
    const WORD_BIT_SIZE: usize,
    const ROUNDS: usize,
    const KEY_SIZE: usize,
    // TODO: Get rid of the following const generics. They can be calculated from the above
    // generics. Unfortunately, stable Rust does not currently support aritmethics with const
    // generics in a const context.
    //
    // This is how the const generics below can be computed from the const generics above:
    // - WORD_SIZE = WORD_BIT_SIZE / 8
    // - BLOCK_SIZE = 2 * WORD_SIZE
    // - EXPANDED_KEY_TABLE_LEN = 2 * (ROUNDS + 1)
    // - KEY_AS_WORDS_LEN = max(KEY_SIZE.div_ceil(WORD_SIZE), 1)
    const WORD_SIZE: usize,
    const BLOCK_SIZE: usize,
    const EXPANDED_KEY_TABLE_LEN: usize,
    const KEY_AS_WORDS_LEN: usize,
> {
    expanded_key_table: [[u8; WORD_SIZE]; EXPANDED_KEY_TABLE_LEN],
}

impl<
    const WORD_BIT_SIZE: usize,
    const ROUNDS: usize,
    const KEY_SIZE: usize,
    const WORD_SIZE: usize,
    const BLOCK_SIZE: usize,
    const EXPANDED_KEY_TABLE_LEN: usize,
    const KEY_AS_WORDS_LEN: usize,
>
    RC5<
        WORD_BIT_SIZE,
        ROUNDS,
        KEY_SIZE,
        WORD_SIZE,
        BLOCK_SIZE,
        EXPANDED_KEY_TABLE_LEN,
        KEY_AS_WORDS_LEN,
    >
{
    #[must_use]
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self {
            expanded_key_table: Self::expand_key(key),
        }
    }

    fn expand_key(key: [u8; KEY_SIZE]) -> [[u8; WORD_BIT_SIZE]; EXPANDED_KEY_TABLE_LEN] {
        let p = p::<WORD_BIT_SIZE, WORD_SIZE>();
        let q = q::<WORD_BIT_SIZE, WORD_SIZE>();

        // Convert key from byte array to a word array.
        let mut key_as_words: [[u8; WORD_SIZE]; KEY_AS_WORDS_LEN] =
            [[0; WORD_SIZE]; KEY_AS_WORDS_LEN];

        for idx in (0..KEY_SIZE).rev() {
            let key_word = &mut key_as_words[idx / WORD_SIZE];
            *key_word = key_word
                .rotate_left(8)
                .wrapping_add(<[u8; WORD_SIZE]>::from_slice(&[key[idx]]));
        }

        // Create expanded key table.
        let mut expanded_key_table: [[u8; WORD_SIZE]; EXPANDED_KEY_TABLE_LEN] =
            [[0; WORD_SIZE]; EXPANDED_KEY_TABLE_LEN];

        expanded_key_table[0] = p;

        for idx in 1..expanded_key_table.len() {
            expanded_key_table[idx] = expanded_key_table[idx - 1].wrapping_add(q);
        }

        // Mix the word array and expanded key table.
        let mut expanded_key_word_idx = 0;
        let mut key_word_idx = 0;
        let mut last_expanded_key_word = [0; WORD_SIZE];
        let mut last_key_word = [0; WORD_SIZE];

        for _ in 0..3 * max(KEY_AS_WORDS_LEN, EXPANDED_KEY_TABLE_LEN) {
            let expanded_key_word = &mut expanded_key_table[expanded_key_word_idx];
            *expanded_key_word = expanded_key_word
                .wrapping_add(last_expanded_key_word)
                .wrapping_add(last_key_word)
                .rotate_left(3);
            last_expanded_key_word = *expanded_key_word;

            let key_word = &mut key_as_words[key_word_idx];
            *key_word = key_word
                .wrapping_add(last_expanded_key_word)
                .wrapping_add(last_key_word)
                .rotate_left(u128::from_le_bytes(<[u8; 16]>::from_slice(
                    &expanded_key_word.wrapping_add(last_key_word),
                )));
            last_key_word = *key_word;

            expanded_key_word_idx = (expanded_key_word_idx + 1) % expanded_key_table.len();
            key_word_idx = (key_word_idx + 1) % key_as_words.len();
        }

        expanded_key_table
    }

    /// Encrypts the plaintext block returning ciphertext block.
    #[must_use]
    pub fn encrypt(&self, plaintext: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let (a, b) = plaintext.split_at(WORD_SIZE);
        let mut a: [u8; WORD_SIZE] = a.try_into().unwrap();
        let mut b: [u8; WORD_SIZE] = b.try_into().unwrap();

        a = a.wrapping_add(self.expanded_key_table[0]);
        b = b.wrapping_add(self.expanded_key_table[1]);

        for idx in 1..=ROUNDS {
            a = a
                .bitxor(b)
                .rotate_left(u128::from_le_bytes(<[u8; 16]>::from_slice(&b)))
                .wrapping_add(self.expanded_key_table[2 * idx]);
            b = b
                .bitxor(a)
                .rotate_left(u128::from_le_bytes(<[u8; 16]>::from_slice(&a)))
                .wrapping_add(self.expanded_key_table[2 * idx + 1]);
        }

        let mut output = [0; BLOCK_SIZE];

        let (left, right) = output.split_at_mut(WORD_SIZE);
        left.copy_from_slice(&a);
        right.copy_from_slice(&b);

        output
    }

    /// Decrypts the ciphertext block returning plaintext block.
    #[must_use]
    pub fn decrypt(&self, ciphertext: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let (a, b) = ciphertext.split_at(WORD_SIZE);
        let mut a: [u8; WORD_SIZE] = a.try_into().unwrap();
        let mut b: [u8; WORD_SIZE] = b.try_into().unwrap();

        for idx in (1..=ROUNDS).rev() {
            b = b
                .wrapping_sub(self.expanded_key_table[2 * idx + 1])
                .rotate_right(u128::from_le_bytes(<[u8; 16]>::from_slice(&a)))
                .bitxor(a);
            a = a
                .wrapping_sub(self.expanded_key_table[2 * idx])
                .rotate_right(u128::from_le_bytes(<[u8; 16]>::from_slice(&b)))
                .bitxor(b);
        }

        b = b.wrapping_sub(self.expanded_key_table[1]);
        a = a.wrapping_sub(self.expanded_key_table[0]);

        let mut output = [0; BLOCK_SIZE];

        let (left, right) = output.split_at_mut(WORD_SIZE);
        left.copy_from_slice(&a);
        right.copy_from_slice(&b);

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc_32_12_16_encrypt_decrypt_a() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ciphertext = [0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_32_12_16_encrypt_decrypt_b() {
        let key = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let plaintext = [0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ciphertext = [0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    // The following test cases are taken from https://www.grc.com/r&d/rc5.pdf.

    #[test]
    fn rc_32_12_16_encrypt_decrypt_c() {
        let key = [0x00; 16];
        let plaintext = [0x00; 8];
        let ciphertext = [0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_32_12_16_encrypt_decrypt_d() {
        let key = [
            0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9,
            0xCE, 0x91,
        ];
        let plaintext = [0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let ciphertext = [0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_32_12_16_encrypt_decrypt_e() {
        let key = [
            0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1,
            0x67, 0x87,
        ];
        let plaintext = [0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        let ciphertext = [0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_32_12_16_encrypt_decrypt_f() {
        let key = [
            0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1,
            0x2B, 0xAF,
        ];
        let plaintext = [0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92];
        let ciphertext = [0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_32_12_16_encrypt_decrypt_g() {
        let key = [
            0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15,
            0x31, 0x25,
        ];
        let plaintext = [0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC];
        let ciphertext = [0xEB, 0x44, 0xE4, 0x15, 0xDA, 0x31, 0x98, 0x24];
        assert_encrypt_decrypt_roundtrip::<32, 12, 16, 4, 8, 26, 4>(key, plaintext, ciphertext);
    }

    // The following test cases are taken from
    // https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4.

    #[test]
    fn rc_8_12_4_encrypt_decrypt() {
        let key = [0x00, 0x01, 0x02, 0x03];
        let plaintext = [0x00, 0x01];
        let ciphertext = [0x21, 0x2A];
        assert_encrypt_decrypt_roundtrip::<8, 12, 4, 1, 2, 26, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_16_16_8_encrypt_decrypt() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let plaintext = [0x00, 0x01, 0x02, 0x03];
        let ciphertext = [0x23, 0xA8, 0xD7, 0x2E];
        assert_encrypt_decrypt_roundtrip::<16, 16, 8, 2, 4, 34, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_32_20_16_encrypt_decrypt() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let plaintext = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let ciphertext = [0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
        assert_encrypt_decrypt_roundtrip::<32, 20, 16, 4, 8, 42, 4>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_64_24_24_encrypt_decrypt() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let plaintext = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let ciphertext = [
            0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71,
            0x78, 0xDA,
        ];
        assert_encrypt_decrypt_roundtrip::<64, 24, 24, 8, 16, 50, 3>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_128_28_32_encrypt_decrypt() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let plaintext = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let ciphertext = [
            0xEC, 0xA5, 0x91, 0x09, 0x21, 0xA4, 0xF4, 0xCF, 0xDD, 0x7A, 0xD7, 0xAD, 0x20, 0xA1,
            0xFC, 0xBA, 0x06, 0x8E, 0xC7, 0xA7, 0xCD, 0x75, 0x2D, 0x68, 0xFE, 0x91, 0x4B, 0x7F,
            0xE1, 0x80, 0xB4, 0x40,
        ];
        assert_encrypt_decrypt_roundtrip::<128, 28, 32, 16, 32, 58, 2>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_24_4_0_encrypt_decrypt() {
        let key = [];
        let plaintext = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let ciphertext = [0x89, 0xCB, 0xDC, 0xC9, 0x52, 0x5A];
        assert_encrypt_decrypt_roundtrip::<24, 4, 0, 3, 6, 10, 1>(key, plaintext, ciphertext);
    }

    #[test]
    fn rc_80_4_12_encrypt_decrypt() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        ];
        let plaintext = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        ];
        let ciphertext = [
            0x9C, 0xB5, 0x9E, 0xCB, 0xA4, 0xEA, 0x84, 0x56, 0x8A, 0x42, 0x78, 0xB0, 0xE1, 0x32,
            0xD5, 0xFC, 0x9D, 0x58, 0x19, 0xD6,
        ];
        assert_encrypt_decrypt_roundtrip::<80, 4, 12, 10, 20, 10, 2>(key, plaintext, ciphertext);
    }

    fn assert_encrypt_decrypt_roundtrip<
        const WORD_BIT_SIZE: usize,
        const ROUNDS: usize,
        const KEY_SIZE: usize,
        const WORD_SIZE: usize,
        const BLOCK_SIZE: usize,
        const EXPANDED_KEY_TABLE_LEN: usize,
        const KEY_AS_WORDS_LEN: usize,
    >(
        key: [u8; KEY_SIZE],
        plaintext: [u8; BLOCK_SIZE],
        ciphertext: [u8; BLOCK_SIZE],
    ) {
        let rc5 = RC5::<
            WORD_BIT_SIZE,
            ROUNDS,
            KEY_SIZE,
            WORD_SIZE,
            BLOCK_SIZE,
            EXPANDED_KEY_TABLE_LEN,
            KEY_AS_WORDS_LEN,
        >::new(key);

        let output_ciphertext = rc5.encrypt(plaintext);
        assert_eq!(output_ciphertext, ciphertext);

        let output_plaintext = rc5.decrypt(output_ciphertext);
        assert_eq!(output_plaintext, plaintext);
    }
}
