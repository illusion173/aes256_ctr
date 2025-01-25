use rand::Rng;
extern crate rand;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 15] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
];

const INVSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const AES_MIX_COLUMNS_MATRIX: [[u8; 4]; 4] = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
];

const AES_INV_MIX_COLUMNS_MATRIX: [[u8; 4]; 4] = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e],
];

const BLOCK_SIZE: usize = 16; // AES block size
const ROUNDS: usize = 14; // AES-256 has 14 rounds
const NONCE_SIZE: usize = 12; // so the size of the physical nonce is 96 bits
const COUNTER_BLOCK_SIZE: usize = 16; // But the size of the counterblock is 128 bits.
const KEY_SIZE: usize = 32; // AES 32 bytes for 256 bit keys
const NK: usize = 8; // Number of words in the key (for AES256)
const NB: usize = 4; // Number of columns in the state (AES)
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; NONCE_SIZE]; // Initialize an array of 16 bytes
    rng.fill(&mut nonce); // Fill the array with random bytes
    nonce
}

pub fn generate_key() -> [u8; COUNTER_BLOCK_SIZE] {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; COUNTER_BLOCK_SIZE]; // Initialize an array of 32 bytes
    rng.fill(&mut key); // Fill the array with random bytes
    println!("{:?}", key);
    key
}

pub struct AES256Ctr {
    key: [u8; KEY_SIZE],
    nonce: [u8; NONCE_SIZE],
    counter_block: [u8; COUNTER_BLOCK_SIZE],
    state: [[u8; NB]; NB],
}

impl AES256Ctr {
    fn clean_slate_for_cipher(&mut self) -> () {
        // Clean the counter
        self.counter_block = AES256Ctr::create_counter_block(self.nonce);

        //Clean State
        self.state = [[0; NB]; NB];
    }
    // Constructor to create a new instance of AES256Ctr
    pub fn new(key: [u8; KEY_SIZE], nonce: [u8; NONCE_SIZE]) -> Self {
        // Generate the counter_block, 16 bytes
        let counter_block = AES256Ctr::create_counter_block(nonce); // Gen the counter block 12 bit
                                                                    // nonce 4 bit counter
        let state: [[u8; NB]; NB] = [[0; NB]; NB]; // fill the state with 0s
        AES256Ctr {
            key,
            nonce,
            counter_block,
            state,
        }
    }

    fn create_counter_block(nonce: [u8; NONCE_SIZE]) -> [u8; COUNTER_BLOCK_SIZE] {
        let mut counter_block = [0u8; COUNTER_BLOCK_SIZE]; // Initialize all to zero
        counter_block[..NONCE_SIZE].copy_from_slice(&nonce); // Set the nonce (first 16 bytes)
        counter_block
    }

    // SubWord applies the S-box transformation to a 32-bit word
    fn sub_word(word: u32) -> u32 {
        let mut result = 0;
        for i in 0..4 {
            let byte = (word >> (8 * (3 - i))) & 0xFF;
            result |= (SBOX[byte as usize] as u32) << (8 * (3 - i));
        }
        result
    }

    // RotWord rotates a 32-bit word (circular shift of 8 bits)
    fn rot_word(&self, word: u32) -> u32 {
        (word << 8) | (word >> 24)
    }

    fn key_expansion(key: &[u8; KEY_SIZE]) -> [u8; 240] {
        let mut round_key = [0u8; 240]; // 15 rounds for AES256 -> 15 * 16 = 240 bytes

        // First NK words are the key itself
        for i in 0..NK {
            round_key[i * 4] = key[i * 4];
            round_key[i * 4 + 1] = key[i * 4 + 1];
            round_key[i * 4 + 2] = key[i * 4 + 2];
            round_key[i * 4 + 3] = key[i * 4 + 3];
        }

        // Generate the remaining round keys
        for i in NK..NB * (ROUNDS + 1) {
            // Load the last 32-bit word from the round key
            let temp = u32::from_be_bytes([
                round_key[(i - 1) * 4],
                round_key[(i - 1) * 4 + 1],
                round_key[(i - 1) * 4 + 2],
                round_key[(i - 1) * 4 + 3],
            ]);

            let mut new_word = temp;

            if i % NK == 0 {
                // RotWord
                new_word = new_word.rotate_left(8);

                // SubWord
                new_word = AES256Ctr::sub_word(new_word);

                // Rcon
                new_word ^= (RCON[i / NK] as u32) << 24;
            }

            if i % NK == 4 {
                // SubWord
                new_word = AES256Ctr::sub_word(new_word);
            }

            // Store the new round key
            let prev = (i - NK) * 4;
            let new_bytes = new_word.to_be_bytes();
            round_key[i * 4] = round_key[prev] ^ new_bytes[0];
            round_key[i * 4 + 1] = round_key[prev + 1] ^ new_bytes[1];
            round_key[i * 4 + 2] = round_key[prev + 2] ^ new_bytes[2];
            round_key[i * 4 + 3] = round_key[prev + 3] ^ new_bytes[3];
        }

        round_key
    }

    fn add_round_key(&mut self, round_key: &[u8; 16]) {
        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] ^= round_key[i * 4 + j];
            }
        }
    }

    fn shift_rows(&mut self) {
        let mut temp: u8;

        // Rotate first row 1 column to left
        temp = self.state[0][1];
        self.state[0][1] = self.state[1][1];
        self.state[1][1] = self.state[2][1];
        self.state[2][1] = self.state[3][1];
        self.state[3][1] = temp;

        // Rotate second row 2 columns to left
        temp = self.state[0][2];
        self.state[0][2] = self.state[2][2];
        self.state[2][2] = temp;

        temp = self.state[1][2];
        self.state[1][2] = self.state[3][2];
        self.state[3][2] = temp;

        // Rotate third row 3 columns to left
        temp = self.state[0][3];
        self.state[0][3] = self.state[3][3];
        self.state[3][3] = self.state[2][3];
        self.state[2][3] = self.state[1][3];
        self.state[1][3] = temp;
    }

    // Function to perform the MixColumns transformation on the state
    fn mix_columns(&mut self) {
        let mut temp = [[0u8; 4]; 4];

        for c in 0..4 {
            // Applying the AES MixColumns matrix
            temp[0][c] = AES256Ctr::gf_mul(0x02, self.state[0][c])
                ^ AES256Ctr::gf_mul(0x03, self.state[1][c])
                ^ AES256Ctr::gf_mul(0x01, self.state[2][c])
                ^ AES256Ctr::gf_mul(0x01, self.state[3][c]);

            temp[1][c] = AES256Ctr::gf_mul(0x01, self.state[0][c])
                ^ AES256Ctr::gf_mul(0x02, self.state[1][c])
                ^ AES256Ctr::gf_mul(0x03, self.state[2][c])
                ^ AES256Ctr::gf_mul(0x01, self.state[3][c]);

            temp[2][c] = AES256Ctr::gf_mul(0x01, self.state[0][c])
                ^ AES256Ctr::gf_mul(0x01, self.state[1][c])
                ^ AES256Ctr::gf_mul(0x02, self.state[2][c])
                ^ AES256Ctr::gf_mul(0x03, self.state[3][c]);

            temp[3][c] = AES256Ctr::gf_mul(0x03, self.state[0][c])
                ^ AES256Ctr::gf_mul(0x01, self.state[1][c])
                ^ AES256Ctr::gf_mul(0x01, self.state[2][c])
                ^ AES256Ctr::gf_mul(0x02, self.state[3][c]);
        }

        // Copy the mixed columns back into the state
        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] = temp[i][j];
            }
        }
    }

    // Function to multiply two bytes in GF(2^8)
    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;

        for _ in 0..8 {
            // If the least significant bit of b is 1, XOR result with a
            if b & 1 != 0 {
                result ^= a;
            }

            // Shift a left by 1 (multiply by x) and reduce modulo 0x11B
            let carry = a & 0x80;
            a <<= 1;
            if carry != 0 {
                a ^= 0x1B; // XOR with the irreducible polynomial (0x11B)
            }

            // Shift b right by 1 (divide by x)
            b >>= 1;
        }
        result
    }

    fn increment_counter(&mut self) {
        let mut carry = 1; // Start with a carry of 1, to increment the counter
                           // Loop through the last 4 bytes (the counter part of the counter_block)
        for i in (NONCE_SIZE..COUNTER_BLOCK_SIZE).rev() {
            let new_value = self.counter_block[i] as u16 + carry as u16; // Add carry to the current byte
            self.counter_block[i] = new_value as u8; // Store the lower 8 bits of the result
            carry = (new_value >> 8) as u8; // Update carry (either 0 or 1)
            if carry == 0 {
                break; // If there's no carry, we are done
            }
        }
    }

    fn sub_bytes(&mut self) {
        for row in self.state.iter_mut() {
            for byte in row.iter_mut() {
                *byte = SBOX[*byte as usize];
            }
        }
    }

    // Function to encrypt a block (AES encryption of the counter block)
    pub fn encrypt_block(&mut self) -> [u8; BLOCK_SIZE] {
        let mut keystream = [0u8; COUNTER_BLOCK_SIZE];

        let round_keys = AES256Ctr::key_expansion(&self.key);

        //Clean State
        self.state = [[0; NB]; NB];

        for i in 0..4 {
            for j in 0..4 {
                self.state[i][j] = self.counter_block[i + 4 * j];
            }
        }

        // Perform the encryption rounds
        // AES-256 uses 14 rounds, 1 initial key addition and 13 rounds of transformation
        // Round 0 - AddRoundKey
        let round_key: &[u8; 16] = round_keys[0..16]
            .try_into()
            .expect("Invalid round key size");
        self.add_round_key(round_key);

        // Rounds 1 to 13 - SubBytes, ShiftRows, MixColumns, and AddRoundKey
        for round in 1..14 {
            let round_key: &[u8; 16] = round_keys[round * 16..(round + 1) * 16]
                .try_into()
                .expect("Invalid round key size");
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(round_key);
        }

        // Round 14 (final round) - SubBytes, ShiftRows, and AddRoundKey
        let round_key: &[u8; 16] = round_keys[14 * 16..15 * 16]
            .try_into()
            .expect("Invalid round key size");
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(round_key);

        // Store the output from the state matrix into the keystream array
        for i in 0..4 {
            for j in 0..4 {
                keystream[i + 4 * j] = self.state[i][j];
            }
        }

        keystream
    }
    // Encrypt the plaintext using AES256 in CTR mode
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        for block_start in (0..plaintext.len()).step_by(COUNTER_BLOCK_SIZE) {
            // Avoids some issues with under/over block encryption
            let block_end = std::cmp::min(block_start + COUNTER_BLOCK_SIZE, plaintext.len());
            let block = &plaintext[block_start..block_end];

            // Really what we are doing here is encrypting the key, then incrementing it.
            let key_stream = self.encrypt_block();

            for i in 0..block.len() {
                ciphertext.push(block[i] ^ key_stream[i]);
            }
            self.increment_counter();
        }
        ciphertext
    }

    // Decrypt the ciphertext (CTR mode is symmetric, so it's the same as encryption)
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        // Clean the counter
        self.counter_block = AES256Ctr::create_counter_block(self.nonce);

        //Clean State
        self.state = [[0; NB]; NB];
        self.encrypt(ciphertext)
    }
}
