extern crate serialize;

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

    pub fn count_duplicate_blocks(block_size: uint, data: &[u8]) -> uint {
        let mut blocks: HashMap<&[u8],uint> = HashMap::new();
        let block_count = data.len() / block_size;
        for block_no in range(0u,block_count)
        {
            let block = data
                .slice(
                    (block_no+0)*block_size,
                    (block_no+1)*block_size);

            // Ugh! Where is setdefault/getdefault ?
            let old = match blocks.find(&block) {
                Some(x) => *x,
                None => 0u
            };
            blocks.insert(block,old + 1u);
        }
        *(blocks.values().max().unwrap())
    }
}
