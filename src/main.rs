use ed25519_dalek::{PublicKey, SecretKey};
use libp2p_core::PeerId;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!(
            "ERROR: no arguments\n{} expects a single argument: base58 string encoding 32 bytes",
            args[0]
        );
        return;
    }
    println!("first arg is {}", args[1]);
    println!("decoding from base58 to bytes");
    let bytes = bs58::decode(&args[1])
        .into_vec()
        .expect("failed to decode from base58");
    println!("bytes are {:x?}", bytes);
    let sk = SecretKey::from_bytes(&bytes).expect("failed to create secret key");
    let pk: PublicKey = (&sk).into();
    let pk = pk.to_bytes();
    println!("public key is {:x?}", pk);
}

#[test]
fn generate() {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let sk = SecretKey::from_bytes(&bytes)
        .expect("this returns `Err` only if the length is wrong; the length is correct; qed");
    let pk: PublicKey = (&sk).into();

    println!(
        "secret key is {:x?}",
        bs58::encode(sk.as_bytes()).into_string()
    );
    println!(
        "public key is {:x?}",
        bs58::encode(pk.as_bytes()).into_string()
    );

    use libp2p_core::identity::ed25519;
    let mut sk = sk.as_ref().to_vec();
    let sk = ed25519::SecretKey::from_bytes(&mut sk).unwrap();
    let kp = ed25519::Keypair::from(sk);
    let pk = libp2p_core::PublicKey::Ed25519(kp.public());
    let peer_id = PeerId::from_public_key(pk);
    println!("peer id is {:x?}", peer_id.to_base58());
}
