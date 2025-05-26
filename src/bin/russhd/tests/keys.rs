#[test]
fn default_key() {
    let openssl_private_key = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD6gSV5iupQhzIXWpXRWqVkaq5LoEceKYEzrQ9ieEesgQAAAIgFMrD+BTKw
/gAAAAtzc2gtZWQyNTUxOQAAACD6gSV5iupQhzIXWpXRWqVkaq5LoEceKYEzrQ9ieEesgQ
AAAEDvJQwgNzblzUOh6SuHq8Bx249G0zByfuqVCKNWW3duf/qBJXmK6lCHMhdaldFapWRq
rkugRx4pgTOtD2J4R6yBAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----"#;

    let openssl_public_key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqBJXmK6lCHMhdaldFapWRqrkugRx4pgTOtD2J4R6yB";

    let private_key = russh::keys::PrivateKey::from_openssh(openssl_private_key).unwrap();
    let public_key = russh::keys::PublicKey::from_openssh(openssl_public_key).unwrap();

    assert_eq!(&public_key, private_key.public_key());
}

#[test]
fn new_keypair() {
    use rand_core::OsRng;

    let key = russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap();

    println!(
        "New private key: \n\n{}",
        key.to_openssh(ssh_encoding::pem::LineEnding::default())
            .unwrap()
            .as_str()
    );
    println!(
        "New public key: \n\n{}\n",
        key.public_key().to_openssh().unwrap()
    );
}
