// Set 1 of the Matasano Cryptopals challenges

use openssl;
use serialize::base64;
use serialize::base64::FromBase64;
use serialize::base64::ToBase64;
use serialize::hex::FromHex;
use serialize::hex::ToHex;
use std::io::BufferedReader;
use std::io::File;
use std::iter::Iterator;
use std::str;
use stdlib_ext::PartialOrdIterator;
use toolbox::xor;
use toolbox::blocks;
use toolbox::lang::CharUnigrams;

#[test]
fn challenge1()
{
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
            .from_hex()
            .unwrap()[]
            .to_base64(base64::STANDARD)[]);
}

#[test]
fn challenge2()
{
    let a_bytes = "1c0111001f010100061a024b53535009181c"
        .from_hex()
        .unwrap();
    let b_bytes = "686974207468652062756c6c277320657965"
        .from_hex()
        .unwrap();
    let result = a_bytes.iter().zip(b_bytes.iter())
        .map(|(a,b)| *a ^ *b )
        .collect::<Vec<u8>>();
    assert_eq!("746865206b696420646f6e277420706c6179",
               result[].to_hex()[]);
}

#[test]
fn challenge3()
{
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        .from_hex()
        .unwrap();

    let model = CharUnigrams::new("data/english_corpus.txt");

    let (_,_,plaintext) = xor::find_best_xor_key(
        ciphertext[],
        |text| model.score_utf8_bytes(text));

    assert_eq!("Cooking MC's like a pound of bacon".as_bytes(),
               plaintext[]);
}

#[test]
fn challenge4()
{
    let mut file = BufferedReader::new(File::open(&Path::new("data/data_s1c4.txt")));
    let model = CharUnigrams::new("data/english_corpus.txt");
    let (_,_,plaintext) = file
        .lines()
        .map(|line| line.unwrap()[].from_hex().unwrap() )
        .map(|line| xor::find_best_xor_key(
            line[],
            |text| model.score_utf8_bytes(text)))
        .partial_max()
        .unwrap();

    assert_eq!("Now that the party is jumping\n".as_bytes(),
               plaintext[]);
}

#[test]
fn challenge5()
{
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let ciphertext = xor::repeat_key_xor(
        "ICE".as_bytes(),
        plaintext.as_bytes());

    assert_eq!(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        ciphertext[].to_hex()[]);
}

#[test]
fn challenge6()
{
    let ciphertext = File::open(&Path::new("data/data_s1c6.txt"))
        .read_to_string()
        .unwrap()[]
        .from_base64()
        .unwrap();

    let model = CharUnigrams::new("data/english_corpus.txt");

    let keysize = xor::infer_xor_keysize(
        2,40,
        ciphertext[]);

    let key_bytes = xor::find_best_repeating_xor_key(
        keysize,
        ciphertext[],
        |text| model.score_utf8_bytes(text));

    let decrypted = xor::repeat_key_xor(
        key_bytes[],
        ciphertext[]);

    assert_eq!("Terminator X: Bring the noise".as_bytes(),
               key_bytes[]);
    assert_eq!("I'm back and".as_bytes(),
               decrypted.slice(0,12));
}

#[test]
fn challenge7()
{
    let ciphertext = File::open(&Path::new("data/data_s1c7.txt"))
        .read_to_string()
        .unwrap()[]
        .from_base64()
        .unwrap();

    let decrypted = openssl::crypto::symm::decrypt(
        openssl::crypto::symm::AES_128_ECB,
        "YELLOW SUBMARINE".as_bytes(),
        vec![],
        ciphertext[]);

    assert_eq!(
        "I'm back and",
        str::from_utf8(decrypted[])
            .unwrap()
            .slice(0,12));
}

#[test]
fn challenge8()
{
    let mut file = BufferedReader::new(File::open(&Path::new("data/data_s1c8.txt")));

    let (_,line_no) = file
        .lines()
        .enumerate()
        .map(|(line_no, hex)| {
            let ciphertext = hex
                .unwrap()[]
                .from_hex()
                .unwrap();
            (line_no,ciphertext)
        })
        .map(|(line_no, ciphertext)| {
            let dupe_blocks = blocks::count_duplicate_blocks(
                16,
                ciphertext[]);
            (dupe_blocks,line_no)
        })
        .max()
        .unwrap();

    assert_eq!(132,line_no);
}
