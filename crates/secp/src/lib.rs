#![doc = include_str!("../README.md")]
#![doc = include_str!("../doc/API.md")]

#[cfg(all(not(feature = "secp256k1"), not(feature = "k256")))]
compile_error!("At least one of the `secp256k1` or `k256` features must be enabled.");

mod arithmetic;
pub mod errors;
mod points;
mod scalars;
mod serde;

pub use points::*;
pub use scalars::*;

mod t {
    use sha2::{Digest, Sha256};
    use subtle::{Choice, ConstantTimeEq};

    pub const PRIVKEY: &[u8; 32] = &[
        254, 237, 105, 209, 200, 130, 84, 7, 141, 199, 110, 17, 65, 127, 3, 163, 108, 0, 97, 33,
        253, 109, 3, 79, 35, 138, 200, 124, 171, 86, 179, 100,
    ];
    fn compute_challenge(r: &Point, pubkey: &Point, msg: &[u8]) -> MaybeScalar {
        let pubkey = pubkey.serialize().clone();
        let r_bytes = r.serialize_xonly();
        let e = r_bytes.iter().cloned().chain(pubkey.iter().cloned());
        let e = e.chain(msg.iter().cloned()).collect::<Vec<u8>>();
        let hash = Sha256::digest(&e);
        MaybeScalar::reduce_from(&hash.into())
    }
    pub struct Signature {
        r: Point,
        s: MaybeScalar,
    }
    impl Signature {
        fn from_bytes(bytes: &[u8]) -> Signature {
            let mut bytes = bytes.to_owned().clone();
            let (r_bytes, s_bytes) = bytes.split_at_mut(32);
            let r_bytes = <[u8; 32]>::try_from(r_bytes).expect("should be 32 bytes");
            Signature {
                // TODO: figure out y is odd or even
                r: Point::lift_x(&r_bytes).unwrap(),
                s: MaybeScalar::from_slice(s_bytes).unwrap(),
            }
        }
        fn to_bytes(&mut self) -> [u8; 64] {
            let s = self.s.serialize();
            let r = self.r.clone().serialize_xonly();
            let bytes = r
                .iter()
                .cloned()
                .chain(s.iter().cloned())
                .collect::<Vec<_>>();
            <[u8; 64]>::try_from(bytes).expect("should be 64 bytes")
        }
    }
    fn schnorr_sign(secret_key: Scalar, message: &[u8]) -> Signature {
        const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        let additional_data = b"Schnorr+SHA256  ";

        let k = rfc6979::generate_k::<Sha256, rfc6979::consts::U32>(
            secret_key.serialize().as_slice().into(),
            hex::decode(ORDER_HEX).unwrap().as_slice().into(),
            message.into(),
            additional_data,
        );

        let mut k = Scalar::reduce_from(&<[u8; 32]>::try_from(k).unwrap());
        // let mut k = Scalar::from(&k);
        let r = k.base_point_mul();
        if !bool::from(r.is_square()) {
            k = -k;
        }
        // k.negate_if(r.is_square().ct_eq(&Choice::from(0)));
        let pubkey: Point = secret_key.base_point_mul();
        let e = compute_challenge(&Point::from(r), &pubkey, message);
        let s = k + secret_key * e;
        Signature { r, s }
    }

    use super::*;
    #[test]
    fn x() {
        let secret_key = Scalar::from_slice(PRIVKEY).unwrap();
        // let public_key = secret_key.base_point_mul();

        for i in 0..10 {
            let formatted = format!("{:064x}", i);
            let msg = Sha256::digest(formatted.to_string());
            // println!("{:?}\n,", formatted);

            let mut sig = schnorr_sign(secret_key, &msg);
            println!("{:?}\n,", sig.to_bytes());

            // let x = schnorr_verify(public_key, sig, &msg);
            // println!("{:?}\n,", x);
        }
    }
}
