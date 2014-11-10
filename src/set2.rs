use serialize::base64::FromBase64;
use std::io::File;
use std::rand;
use std::str;
use toolbox;

#[test]
fn challenge9() {
    assert_eq!(
        "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
        toolbox::pad::pkcs7("YELLOW SUBMARINE".as_bytes(),20).as_slice());
}

#[test]
fn challenge10() {
    let ciphertext = File::open(&Path::new("data/data_s2c10.txt"))
        .read_to_string()
        .unwrap()
        .as_slice()
        .from_base64()
        .unwrap();

    let plaintext = toolbox::crypto::cbc_decrypt(
        "YELLOW SUBMARINE".as_bytes(),
        ciphertext.as_slice(),
        &[0u8, ..16]);

    assert_eq!(Some("I'm back and I'm ringin' the bell \nA rockin' on th"),
               str::from_utf8(plaintext.slice(0,50)));
}

#[test]
fn challenge11() {
    fn rand(max:uint) -> uint {
        rand::random::<uint>()%max
    }

    fn adversary_encrypter(use_ecb: bool, msg: &[u8]) -> Vec<u8>
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
            ciphertext = toolbox::crypto::ecb_encrypt(key.as_slice(),padded_msg.as_slice(),iv.as_slice());
        } else {
            ciphertext = toolbox::crypto::cbc_encrypt(key.as_slice(),padded_msg.as_slice(),iv.as_slice());
        }
        ciphertext
    }
    

    for i in range(0u,100) {
        let use_ecb = rand(2) > 0;
        let detected_ecb_mode = toolbox::crypto::uses_ecb_mode(
            |msg| adversary_encrypter(use_ecb,msg));

        println!("{}: {},{}",i,detected_ecb_mode, use_ecb);
        assert_eq!(detected_ecb_mode, use_ecb);
    }
}
