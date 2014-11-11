use serialize::base64::FromBase64;
use std::io::File;
use std::rand;
use std::str;
use toolbox;

#[test]
fn challenge9() {
    assert_eq!(
        "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
        toolbox::pad::pkcs7("YELLOW SUBMARINE".as_bytes(),20)[]);
}

#[test]
fn challenge10() {
    let ciphertext = File::open(&Path::new("data/data_s2c10.txt"))
        .read_to_string()
        .unwrap()[]
        .from_base64()
        .unwrap();

    let plaintext = toolbox::crypto::cbc_decrypt(
        "YELLOW SUBMARINE".as_bytes(),
        ciphertext[],
        &[0u8, ..16]);

    assert_eq!(Some("I'm back and I'm ringin' the bell \nA rockin' on th"),
               str::from_utf8(plaintext.slice(0,50)));
}

#[test]
fn challenge11() {
    fn rand(max:uint) -> uint {
        rand::random::<uint>()%max
    }

    fn oracle(use_ecb: bool, msg: &[u8]) -> Vec<u8>
    {
        let key = Vec::from_fn(16,|_| rand(256) as u8);
        let iv = Vec::from_fn(16,|_| rand(256) as u8);
        
        let padding_before: uint = rand(6) + 5;
        let padding_after: uint  = rand(6) + 5;
        let mut padded_msg: Vec<u8>= Vec::new();
        padded_msg.grow(padding_before,rand(255) as u8);
        padded_msg.push_all(msg);
        padded_msg.grow(padding_after,rand(255) as u8);

        let ciphertext: Vec<u8>;
        if use_ecb {
            ciphertext = toolbox::crypto::ecb_encrypt(key[],padded_msg[],iv[]);
        } else {
            ciphertext = toolbox::crypto::cbc_encrypt(key[],padded_msg[],iv[]);
        }
        ciphertext
    }
    

    for i in range(0u,100) {
        let use_ecb = rand(2) > 0;
        let detected_ecb_mode = toolbox::crypto::uses_ecb_mode(
            |msg| oracle(use_ecb,msg));

        println!("{}: {},{}",i,detected_ecb_mode, use_ecb);
        assert_eq!(detected_ecb_mode, use_ecb);
    }
}


#[test]
fn challenge12()
{
    fn oracle(data:&[u8]) -> Vec<u8> {
        let key = "yELlOW SuBMaRiNe".as_bytes();
        
        let hidden_plaintext = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
            .from_base64()
            .unwrap();

        let mut plaintext = Vec::<u8>::new();
        plaintext.push_all(data);
        plaintext.push_all(hidden_plaintext[]);
        let ciphertext = toolbox::crypto::ecb_encrypt(key[],plaintext[],[0,..16]);
        ciphertext
    }

    let oracle_uses_ecb = toolbox::crypto::uses_ecb_mode(oracle);
    assert_eq!(oracle_uses_ecb, true);

    let (oracle_block_size,oracle_suffix_len) = toolbox::blocks::analyze_oracle(oracle);
    assert_eq!(oracle_block_size,16);
    assert_eq!(oracle_suffix_len,138);

    let decrypted = toolbox::crypto::ecb_suffix_decrypter(oracle);
    assert_eq!(Some("Rollin' in my 5.0\nWith my rag-top down so my hair can blow"),
               str::from_utf8(decrypted.slice(0,58)));
}

