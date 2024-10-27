usage:

```rust
pub const PRIVKEY: &[u8; 32] = &[
    254, 237, 105, 209, 200, 130, 84, 7, 141, 199, 110, 17, 65, 127, 3, 163, 108, 0, 97, 33, 253,
    109, 3, 79, 35, 138, 200, 124, 171, 86, 179, 100,
];

    #[test]
    fn test_sigs() {
        let secret_key = secp::Scalar::from_slice(PRIVKEY).unwrap();
        for i in 0..10 {
            let formatted = format!("{:064x}", i);
            let msg = Sha256::digest(hex::decode(formatted).unwrap());
            let mut sig = schnorr_sign(secret_key, &msg.try_into().unwrap()).unwrap();
            let sig_bytes = sig.to_bytes();
            let Signature { rx, s } = Signature::from_bytes(&sig_bytes).unwrap();
            assert_eq!(rx, sig.rx);
            assert_eq!(s, sig.s);
            assert!(schnorr_verify(secret_key.base_point_mul(), sig, &msg));
        }
    }
```
