//use std::io::BufferedReader;
use serialize::base64::FromBase64;
use std::io::File;
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
        &[0u8, ..16],
        16);

    assert_eq!(Some("I'm back and I'm ringin' the bell \nA rockin' on th"),
               str::from_utf8(plaintext.slice(0,50)));
}
