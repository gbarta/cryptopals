
pub mod lang {
    use std;
    use std::io::File;
    use std::str;

    const MAX_CHAR_CODE: uint = 128; // only low ascii for now

    pub struct CharUnigrams {
        // Stores log-probability by char-code
        stats : Vec<f32>
    }

    impl CharUnigrams {
        pub fn new(filename:&str) -> CharUnigrams {
            let corpus = File::open(&Path::new(filename))
                .read_to_string()
                .unwrap();

            let mut counts: Vec<uint> = Vec::from_fn(MAX_CHAR_CODE,|_| 1);
            let mut total = MAX_CHAR_CODE;
            for ch in corpus.as_slice().chars()
            {
                total += 1;
                let ch_code = ch as uint;
                if ch_code < MAX_CHAR_CODE
                {
                    counts[ch_code] += 1;
                }
            }

            let result: Vec<f32> = Vec::from_fn(MAX_CHAR_CODE,|count| {
                let prob = counts[count] as f32 / total as f32;
                prob.ln()
            });
            CharUnigrams { stats: result }
        }

        pub fn score_str(&self, text:&str) -> f32 {
            let mut prob = 0.0;
            for ch in text.chars()
            {
                let ch_code = ch as uint;
                if ch_code < MAX_CHAR_CODE
                {
                    prob += self.stats[ch_code];
                }
            }
            prob
        }

        pub fn score_utf8_bytes(&self, bytes: &[u8]) -> f32 {
            match str::from_utf8(bytes) {
                Some(s) => self.score_str(s),
                None => std::f32::NEG_INFINITY
            }
        }
    }
}

pub mod hamming {
    fn byte_distance(a:u8,b:u8) -> uint {
        let mut mask = a ^ b;
        let mut dist = 0u;
        for _ in range(0u,8)
        {
            if (mask&1) == 1
            {
                dist += 1;
            }
            mask >>= 1;
        }
        dist
    }

    pub fn distance(a:&[u8],b:&[u8]) -> uint {
        a.iter().zip(b.iter())
            .map(|(a,b):(&u8,&u8)| byte_distance(*a,*b))
            .fold(0u,|a,b| a+b)
    }

    #[test]
    fn test_hamming_distance()
    {
        assert_eq!(1,byte_distance(1,0));
        assert_eq!(1,byte_distance(2,0));
        assert_eq!(1,byte_distance(4,0));
        assert_eq!(1,byte_distance(8,0));
        assert_eq!(1,byte_distance(16,0));
        assert_eq!(1,byte_distance(32,0));
        assert_eq!(1,byte_distance(64,0));
        assert_eq!(1,byte_distance(128,0));

        assert_eq!(8,byte_distance(255,0));
        assert_eq!(7,byte_distance(127,0));
        assert_eq!(0,byte_distance(0,0));

        assert_eq!(2,byte_distance(16,32));
        
        let dist = distance(
            "this is a test".as_bytes(),
            "wokka wokka!!!".as_bytes());
        assert_eq!(dist,37u);
    }
}

pub mod xor {
    use std::iter::AdditiveIterator;
    use stdlib_ext::PartialOrdIterator;

    fn de_xor(cipher: &[u8],xor:u8) -> Vec<u8> {
        cipher
            .iter()
            .map(|c| c^xor )
            .collect::<Vec<u8>>()
    }

    pub fn find_best_xor_key(cipher: &[u8],scorer:|&[u8]|->f32) -> (f32,u8,Vec<u8>) {
        range(0u,255)
            .map(|xor| xor as u8 )
            .map(|xor| (xor,de_xor(cipher,xor)) )
            .map(|(xor,plain)| (scorer(plain.as_slice()),xor,plain) )
            .partial_max()
            .unwrap()
    }

    pub fn repeat_key_xor(key:&[u8],data:&[u8]) -> Vec<u8> {
        let key_len = key.len();
        data.iter()
            .enumerate()
            .map(|(idx,c):(uint,&u8)| *c ^ key[idx%key_len])
            .collect::<Vec<u8>>()
    }

    pub fn infer_xor_keysize(min_keysize:uint, max_keysize:uint,ciphertext:&[u8]) -> uint {
        let ciphertext_len = ciphertext.len();
        let (_, keysize) = range(min_keysize,max_keysize)
            .map(|keysize| {
                let num_comparisons = (ciphertext_len / keysize) - 1;
                let total_hamming_dist: uint = range(0u,num_comparisons)
                    .map(|block| 
                         super::hamming::distance(
                             ciphertext.as_slice().slice((block+0)*keysize,(block+1)*keysize),
                             ciphertext.as_slice().slice((block+1)*keysize,(block+2)*keysize)))
                    .sum();
                (total_hamming_dist as f32 / (num_comparisons*keysize) as f32,keysize)
            })
            .partial_min()
            .unwrap();
        keysize
    }

    pub fn find_best_repeating_xor_key(keysize: uint, ciphertext: &[u8], scorer: |&[u8]|->f32) -> Vec<u8> {
        // scatter into blocks for each char of the key
        let mut key_char_blocks : Vec<Vec<u8>> = Vec::from_fn(keysize,|_| Vec::new());
        for (i,b) in ciphertext.iter().enumerate()
        {
            let block_id = i % keysize;
            key_char_blocks[block_id].push(*b);
        }

        key_char_blocks
            .iter()
            .map(|block| find_best_xor_key(block.as_slice(),|t|scorer(t)))
            .map(|(_,xor,_)| xor)
            .collect::<Vec<u8>>()
    }
}

pub mod blocks {
    use std::collections::HashMap;

    pub fn has_duplicate_blocks(block_size: uint, data: &[u8]) -> bool {
        count_duplicate_blocks(block_size, data) > 0
    }

    pub fn count_duplicate_blocks(block_size: uint, data: &[u8]) -> uint {
        let mut blocks: HashMap<&[u8],bool> = HashMap::new();
        let block_count = data.len() / block_size;
        for block_no in range(0u,block_count)
        {
            let block = data
                .slice(
                    (block_no+0)*block_size,
                    (block_no+1)*block_size);

            blocks.insert(block,true);
        }
        block_count - blocks.values().count()
    }
}

pub mod pad {
    pub trait Pkcs7Padding {
        fn pkcs7_extend(&mut self, block_size:uint) -> ();
    }

    impl Pkcs7Padding for Vec<u8> {
        fn pkcs7_extend(&mut self, block_size:uint) -> () {
            let data_len = self.len();
            let padding = block_size - data_len%block_size;
            for _ in range(0,padding)
            {
                self.push(padding as u8)
            }
        }
    }

    pub fn pkcs7(data: &[u8], block_size:uint) -> Vec<u8> {
        let mut padded = data.to_vec();
        padded.pkcs7_extend(block_size);
        padded
    }

    #[test]
    fn test_pkcs7_padding()
    {
        assert_eq!("1234567890123456789\x01".as_bytes(),
                   pkcs7("1234567890123456789".as_bytes(),20).as_slice());
        assert_eq!("1234567890\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a".as_bytes(),
                   pkcs7("1234567890".as_bytes(),20).as_slice());

        // If there is no room for padding, we need a whole extra block
        assert_eq!("12345678901234567890\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14".as_bytes(),
                    pkcs7("12345678901234567890".as_bytes(),20).as_slice());
    }
}

pub mod crypto {
    use openssl;
    use super::pad::Pkcs7Padding;

    // Implement cbc mode decrypt on top of openssl ecb mode
    pub fn cbc_decrypt(key:&[u8], data: &[u8], iv:&[u8]) -> Vec<u8> {
        let block_size = 16u;
        let mut decrypted: Vec<u8> = Vec::new();

        // data should already be padded to a multiple of the block_size.
        // We preprocess the data by prefixing with the iv to act as
        // simulated previous block of ciphertext, and suffixing with
        // the iv to provide a sacrificial block at the end so that
        // we can ask the openssl routine to decrypt 2 blocks and throw the second away
        // in order to avoid it attempting to strip padding on a non-final block
        assert_eq!(iv.len(), block_size);
        assert_eq!(data.len() % block_size, 0);
        let mut preproc = iv.to_vec();
        preproc.push_all(data);
        preproc.push_all(iv);
        assert_eq!(preproc.len() % block_size, 0);

        let block_count = preproc.len() / block_size;
        for block_no in range(1u,block_count - 1)
        {
            let block_start = block_no*block_size;

            // ECB decrypt the block and a sacrificial block
            let mut decrypted_block = openssl::crypto::symm::decrypt(
                openssl::crypto::symm::AES_128_ECB,
                key,
                Vec::new(),
                preproc.slice(block_start,block_start + 2*block_size));

            // XOR with previous ciphertext block to turn it into CBC
            // Also trim everything after the first block
            decrypted_block = super::xor::repeat_key_xor(
                preproc.slice(block_start - block_size,block_start),
                decrypted_block.slice(0,block_size));
            
            // Store the single decrypted block
            decrypted.push_all(decrypted_block.slice(0,block_size));
        }

        // Remove padding at the end
        let decrypted_len = decrypted.len();
        let padding = decrypted[decrypted_len-1] as uint;
        decrypted.slice(0,decrypted_len-padding).to_vec()
    }

    // Implement cbc mode decrypt on top of openssl ecb mode
    pub fn cbc_encrypt(key:&[u8], data: &[u8], iv:&[u8]) -> Vec<u8> {
        let block_size = 16u;
        let mut encrypted: Vec<u8> = Vec::new();

        assert_eq!(iv.len(), block_size);
        let mut prev_cipherblock = iv.to_vec();
        let mut preproc = data.to_vec();
        preproc.pkcs7_extend(block_size);

        let block_count = preproc.len() / block_size;
        for block_no in range(0u,block_count)
        {
            let block_start = block_no * block_size;

            // XOR with previous ciphertext block to turn it into CBC
            let xor_block = super::xor::repeat_key_xor(
                prev_cipherblock.as_slice(),
                preproc.slice(block_start, block_start + block_size));

            // ECB encrypt
            let ecb_block = openssl::crypto::symm::encrypt(
                openssl::crypto::symm::AES_128_ECB,
                key,
                Vec::new(),
                xor_block.as_slice());

            // Store the single decrypted block, but skip any padding which
            // may have been added by ecb mode openssl
            let encrypted_block = ecb_block.slice(0,block_size);

            // store the cipherblock for the next xor
            prev_cipherblock = encrypted_block.to_vec();

            encrypted.push_all(encrypted_block);
        }
        encrypted
    }

    pub fn ecb_decrypt(key:&[u8], data: &[u8], iv:&[u8]) -> Vec<u8> {
        // match signature of the cbc version
        openssl::crypto::symm::decrypt(
            openssl::crypto::symm::AES_128_ECB,
            key,
            iv.to_vec(),
            data)
    }

    pub fn ecb_encrypt(key:&[u8], data: &[u8], iv:&[u8]) -> Vec<u8> {
        // match signature of the cbc version
        openssl::crypto::symm::encrypt(
            openssl::crypto::symm::AES_128_ECB,
            key,
            iv.to_vec(),
            data)
    }

    pub fn uses_ecb_mode(crypter: |msg:&[u8]| -> Vec<u8>) -> bool
    {
        // Construct a message that spans three complete blocks.
        // This means that at least two complete blocks will be
        // occupied by the message no matter how it is padded.
        let msg = Vec::from_elem(16*3, 'A' as u8);
        let ciphertext = crypter(msg.as_slice());
        super::blocks::has_duplicate_blocks(16,ciphertext.as_slice())
    }
    

    #[test]
    fn test_cbc_mode()
    {
        let msg = "The cake is a lie, the cake is a lie, THE CAKE IS A LIE!".as_bytes();
        let key = "yellow submarine".as_bytes();

        let iv1 = [0u8, ..16];
        let ciphertext1 = cbc_encrypt(key,msg,iv1);
        let plaintext1  = cbc_decrypt(key,ciphertext1.as_slice(),iv1);

        let iv2 = [8u8, ..16];
        let ciphertext2 = cbc_encrypt(key,msg,iv2);
        let plaintext2  = cbc_decrypt(key,ciphertext2.as_slice(),iv2);

        assert!(ciphertext1 != ciphertext2);
        assert_eq!(msg,plaintext1.as_slice());
        assert_eq!(msg,plaintext2.as_slice());
    }
}
