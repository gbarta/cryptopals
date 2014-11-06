use toolbox::pad;

#[test]
fn challenge9()
{
    assert_eq!(
        "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(),
        pad::pkcs7("YELLOW SUBMARINE".as_bytes(),20).as_slice());
}
