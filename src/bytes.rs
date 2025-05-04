use core::cmp::min;

pub trait ByteIntegerExt {
    fn from_slice(s: &[u8]) -> Self;

    fn bitxor(self, rhs: Self) -> Self;
    fn rotate_left(self, n: u128) -> Self;
    fn rotate_right(self, n: u128) -> Self;
    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
}

impl<const N: usize> ByteIntegerExt for [u8; N] {
    fn from_slice(s: &[u8]) -> [u8; N] {
        let mut output = [0; N];

        let output_len = output.len();
        let range = ..min(s.len(), output_len);
        output[range].copy_from_slice(&s[range]);

        output
    }

    fn bitxor(self, rhs: [u8; N]) -> [u8; N] {
        let mut output = [0; N];

        for idx in 0..self.len() {
            output[idx] = self[idx] ^ rhs[idx];
        }

        output
    }

    fn rotate_left(self, n: u128) -> [u8; N] {
        rotate(self, n, rotate_left_dest_bit_idx)
    }

    fn rotate_right(self, n: u128) -> [u8; N] {
        rotate(self, n, rotate_right_dest_bit_idx)
    }

    fn wrapping_add(self, rhs: [u8; N]) -> [u8; N] {
        let mut output = [0; N];

        let mut carry = false;
        for idx in 0..self.len() {
            let temp_sum: u16 = u16::from(self[idx]) + u16::from(rhs[idx]) + u16::from(carry);
            carry = temp_sum >> 8 > 0;
            output[idx] = temp_sum as u8;
        }

        output
    }

    fn wrapping_sub(self, rhs: [u8; N]) -> [u8; N] {
        let mut output = [0; N];

        let mut borrow = false;
        for idx in 0..self.len() {
            let mut temp_diff: i16 = i16::from(self[idx]) - i16::from(rhs[idx]) - i16::from(borrow);
            borrow = temp_diff < 0;
            if borrow {
                temp_diff += (1 << 8) as i16;
            }
            output[idx] = temp_diff as u8;
        }

        output
    }
}

fn rotate<const N: usize>(
    value: [u8; N],
    n: u128,
    get_dest_bit_idx: fn(usize, usize, usize) -> usize,
) -> [u8; N] {
    let num_bytes = value.len();
    let num_bits = num_bytes * 8;

    // Normalize the rotation amount to a value between 0 and num_bits - 1.
    let n_normalized = {
        let mut num_bits = num_bits as u128;
        if !u128::is_power_of_two(num_bits) {
            num_bits = u128::next_power_of_two(num_bits) >> 1;
        }
        n % num_bits
    } as usize;
    if n_normalized == 0 {
        // If the rotation amount is 0, just return self.
        return value;
    }

    let mut output = [0; N];

    for idx in 0..num_bits {
        let dest_bit_idx = get_dest_bit_idx(n_normalized, idx, num_bits);
        let dest_byte_idx = dest_bit_idx / 8;
        let dest_bit_shift = dest_bit_idx % 8;

        let src_byte_idx = idx / 8;
        let src_bit_shift = idx % 8;
        let src_bit = value[src_byte_idx] >> src_bit_shift;

        output[dest_byte_idx] |= src_bit << dest_bit_shift;
    }

    output
}

fn rotate_left_dest_bit_idx(n: usize, i: usize, num_bits: usize) -> usize {
    (i + n) % num_bits
}

fn rotate_right_dest_bit_idx(n: usize, i: usize, num_bits: usize) -> usize {
    if n > i { num_bits - (n - i) } else { i - n }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_2_a() {
        assert_eq!(<[u8; 2]>::from_slice(&[0x01]), [0x01, 0x00]);
    }

    #[test]
    fn from_slice_2_b() {
        assert_eq!(<[u8; 2]>::from_slice(&[0x01, 0x02]), [0x01, 0x02]);
    }

    #[test]
    fn from_slice_2_c() {
        assert_eq!(<[u8; 2]>::from_slice(&[0x01, 0x02, 0x03]), [0x01, 0x02]);
    }

    #[test]
    fn rotate_left_1_a() {
        assert_rotate_left([0b0000_0001], 1, [0b0000_0010]);
    }

    #[test]
    fn rotate_left_1_b() {
        assert_rotate_left([0b1000_0000], 1, [0b0000_0001]);
    }

    #[test]
    fn rotate_left_1_c() {
        assert_rotate_left([0b0000_0001], 2, [0b0000_0100]);
    }

    #[test]
    fn rotate_left_1_d() {
        assert_rotate_left([0b1100_0011], 10, [0b0000_1111]);
    }

    #[test]
    fn rotate_left_2_a() {
        assert_rotate_left([0b0000_0001, 0b0000_0001], 1, [0b0000_0010, 0b0000_0010]);
    }

    #[test]
    fn rotate_left_2_b() {
        assert_rotate_left([0b1000_0000, 0b1000_0000], 1, [0b0000_0001, 0b0000_0001]);
    }

    #[test]
    fn rotate_left_2_c() {
        assert_rotate_left([0b0000_0001, 0b0000_0001], 2, [0b0000_0100, 0b0000_0100]);
    }

    #[test]
    fn rotate_left_3_a() {
        assert_rotate_left([0x8D, 0x0A, 0xBF], 12520077, [0xE1, 0xB7, 0x51]);
    }

    #[test]
    fn rotate_left_3_b() {
        assert_rotate_left([0xD8, 0x43, 0xC7], 2272123, [0x3A, 0xC6, 0x1E]);
    }

    #[test]
    fn rotate_left_4_a() {
        assert_rotate_left([87, 178, 252, 72], 1335181668, [116, 37, 203, 143]);
    }

    #[test]
    fn rotate_left_4_b() {
        assert_rotate_left([233, 70, 93, 91], 348653453, [107, 43, 221, 168]);
    }

    #[test]
    fn rotate_right_1_a() {
        assert_rotate_right([0b0000_0001], 0b0000_0001, [0b1000_0000]);
    }

    #[test]
    fn rotate_right_1_b() {
        assert_rotate_right([0b1000_0000], 0b0000_0001, [0b0100_0000]);
    }

    #[test]
    fn wrapping_add_1_a() {
        assert_wrapping_add([0x01], [0x01], [0x02]);
    }

    #[test]
    fn wrapping_add_1_b() {
        assert_wrapping_add([0xFF], [0x01], [0x00]);
    }

    #[test]
    fn wrapping_add_2_a() {
        assert_wrapping_add([0x00, 0x01], [0x01, 0x00], [0x01, 0x01]);
    }

    #[test]
    fn wrapping_add_2_b() {
        assert_wrapping_add([0xFF, 0xFF], [0x01, 0x00], [0x00, 0x00]);
    }

    #[test]
    fn wrapping_add_3_a() {
        assert_wrapping_add([0x00, 0x01, 0x02], [0x02, 0x01, 0x00], [0x02, 0x02, 0x02]);
    }

    #[test]
    fn wrapping_add_3_b() {
        assert_wrapping_add([0xFF, 0xFF, 0xFF], [0x01, 0x00, 0x00], [0x00, 0x00, 0x00]);
    }

    #[test]
    fn wrapping_add_4_a() {
        assert_wrapping_add([0, 17, 34, 51], [51, 226, 71, 212], [51, 243, 105, 7]);
    }

    #[test]
    fn wrapping_add_4_b() {
        assert_wrapping_add([68, 85, 102, 119], [32, 236, 46, 216], [100, 65, 149, 79]);
    }

    #[test]
    fn wrapping_sub_1_a() {
        assert_wrapping_sub([0x01], [0x01], [0x00]);
    }

    #[test]
    fn wrapping_sub_1_b() {
        assert_wrapping_sub([0x00], [0x01], [0xFF]);
    }

    #[test]
    fn wrapping_sub_2_a() {
        assert_wrapping_sub([0x01, 0x00], [0x00, 0x01], [0x01, 0xFF]);
    }

    #[test]
    fn wrapping_sub_2_b() {
        assert_wrapping_sub([0x00, 0x00], [0x01, 0x00], [0xFF, 0xFF]);
    }

    #[test]
    fn wrapping_sub_4_a() {
        assert_wrapping_sub([207, 8, 139, 158], [6, 226, 232, 21], [201, 38, 162, 136]);
    }

    fn assert_rotate_left<const N: usize>(value: [u8; N], n: u128, expected: [u8; N]) {
        let output = value.rotate_left(n);
        assert_eq!(output, expected);
    }

    fn assert_rotate_right<const N: usize>(value: [u8; N], n: u128, expected: [u8; N]) {
        let output = value.rotate_right(n);
        assert_eq!(output, expected);
    }

    fn assert_wrapping_add<const N: usize>(lhs: [u8; N], rhs: [u8; N], expected: [u8; N]) {
        let output = lhs.wrapping_add(rhs);
        assert_eq!(output, expected);
    }

    fn assert_wrapping_sub<const N: usize>(lhs: [u8; N], rhs: [u8; N], expected: [u8; N]) {
        let output = lhs.wrapping_sub(rhs);
        assert_eq!(output, expected);
    }
}
