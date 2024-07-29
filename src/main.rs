use rfc6979::consts::U32;
use secp::{MaybeScalar, Point, Scalar};
use sha2::{Digest, Sha256};

pub const PRIVKEY: &[u8; 32] = &[
    254, 237, 105, 209, 200, 130, 84, 7, 141, 199, 110, 17, 65, 127, 3, 163, 108, 0, 97, 33, 253,
    109, 3, 79, 35, 138, 200, 124, 171, 86, 179, 100,
];

pub struct Signature {
    rx: [u8; 32],
    s: MaybeScalar,
}
impl Signature {
    fn from_bytes(bytes: &[u8]) -> Signature {
        let mut bytes = bytes.to_owned().clone();
        let (r_bytes, s_bytes) = bytes.split_at_mut(32);
        let r_bytes = <[u8; 32]>::try_from(r_bytes).expect("should be 32 bytes");
        Signature {
            // TODO: figure out y is odd or even
            // r: Point::lift_x(&r_bytes).unwrap().to_odd_y(),
            rx: r_bytes,
            s: MaybeScalar::from_slice(s_bytes).unwrap(),
        }
    }
    fn to_bytes(&mut self) -> [u8; 64] {
        let s = self.s.serialize();
        let r = self.rx;
        let bytes = r
            .iter()
            .cloned()
            .chain(s.iter().cloned())
            .collect::<Vec<_>>();
        <[u8; 64]>::try_from(bytes).expect("should be 64 bytes")
    }
}

fn main() {
    pub const SIG1: &[u8; 64] = &[
        0x78, 0x7a, 0x84, 0x8e, 0x71, 0x04, 0x3d, 0x28, 0x0c, 0x50, 0x47, 0x0e, 0x8e, 0x15, 0x32,
        0xb2, 0xdd, 0x5d, 0x20, 0xee, 0x91, 0x2a, 0x45, 0xdb, 0xdd, 0x2b, 0xd1, 0xdf, 0xbf, 0x18,
        0x7e, 0xf6, 0x70, 0x31, 0xa9, 0x88, 0x31, 0x85, 0x9d, 0xc3, 0x4d, 0xff, 0xee, 0xdd, 0xa8,
        0x68, 0x31, 0x84, 0x2c, 0xcd, 0x00, 0x79, 0xe1, 0xf9, 0x2a, 0xf1, 0x77, 0xf7, 0xf2, 0x2c,
        0xc1, 0xdc, 0xed, 0x05,
    ];
    let secret_key = Scalar::from_slice(PRIVKEY).unwrap();
    // let secret_key = k256::SecretKey::from_slice(PRIVKEY).unwrap();
    // let secret_key = Scalar::from_slice(PRIVKEY).unwrap();
    let secret_key = secp::Scalar::from(secret_key);
    let public_key = secret_key.base_point_mul();
    let message = b"no fucking way";
    let msg = Sha256::digest(message);

    let signature = schnorr_sign(secret_key, &msg);
    let mut x = SIG1.clone();
    Signature::from_bytes(x.as_slice());
    let x = schnorr_sign(secret_key, &msg);
    let is_valid = schnorr_verify(public_key, x, &msg);
    // println!(
    //     "OG POINT {:?} {}",
    //     // signature.r,
    //     signature
    //         .r
    //         .serialize_xonly()
    //         .iter()
    //         .cloned()
    //         .chain(signature.s.serialize().iter().cloned())
    //         .collect::<Vec<_>>(),
    //     is_valid
    // );
    // assert!(schnorr_verify(public_key, signature, &msg));
}

fn swap_endian(slice: &[u8]) -> Vec<u8> {
    slice.iter().cloned().rev().collect()
}

fn compute_challenge(r: &Point, pubkey: &Point, msg: &[u8]) -> MaybeScalar {
    let pubkey = pubkey.serialize().clone();
    let r_bytes = r.serialize_xonly();
    let e = r_bytes.iter().cloned().chain(pubkey.iter().cloned());
    let e = e.chain(msg.iter().cloned()).collect::<Vec<u8>>();

    let hash = Sha256::digest(&e);
    MaybeScalar::reduce_from(&hash.into())
}

fn schnorr_sign(secret_key: Scalar, message: &[u8]) -> Signature {
    const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    let additional_data = b"Schnorr+SHA256  ";
    let k = rfc6979::generate_k::<Sha256, U32>(
        secret_key.serialize().as_slice().into(),
        hex::decode(ORDER_HEX).unwrap().as_slice().into(),
        message.into(),
        additional_data,
    );

    let mut k = Scalar::from_slice(&k.as_slice()).unwrap();
    let r = k.base_point_mul();

    if !bool::from(r.is_square()) {
        k = -k;
    }

    let pubkey = secret_key.base_point_mul();

    let e = compute_challenge(&r.to_odd_y(), &pubkey, message);
    let s = k + e * secret_key;
    Signature {
        rx: r.serialize_xonly(),
        s,
    }
}

fn schnorr_verify(public_key: Point, signature: Signature, message: &[u8]) -> bool {
    let Signature { rx, s } = signature;
    let e = compute_challenge(&Point::from_slice(&rx).unwrap(), &public_key, message);
    let r = Point::from_slice(&rx).unwrap();
    s.base_point_mul() == r + e * public_key
}

mod test {

    use super::*;

    #[test]
    fn print_sigs() {
        let secret_key = secp::Scalar::from_slice(PRIVKEY).unwrap();
        for i in 0..10 {
            let formatted = format!("{:064x}", i);
            let msg = Sha256::digest(formatted.to_string());
            // println!("{:?}\n,", formatted);

            let mut sig = schnorr_sign(secret_key, &msg);
            // println!("{:?}\n,", sig.to_bytes());
            let sig_bytes = sig.to_bytes();
            let Signature { rx, s } = Signature::from_bytes(sig_bytes.as_slice());
            println!("{:?}", sig.rx);
            assert_eq!(rx, sig.rx);
            assert_eq!(s, sig.s);
        }
    }
    #[test]
    fn test_sig() {
        // let public_key = Point::from_slice(PK1).unwrap();
        // let r_array = <[u8; 32]>::try_from(&SIG1[0..32]).expect("should be 32 bytes");
        // let s_array = <[u8; 32]>::try_from(&SIG1[32..]).expect("should be 32 bytes");

        // let r = Point::lift_x(&r_array).unwrap().to_odd_y();
        // let s = Scalar::from_slice(&s_array);
        // let signature = Signature {
        //     r,
        //     s: MaybeScalar::from(s.unwrap()).unwrap().into(),
        // };

        // assert!(schnorr_verify(public_key, signature, MSG1));

        // let public_key = Point::from_slice(PK2).unwrap();
        // let r_array = <[u8; 32]>::try_from(&SIG2[0..32]).expect("should be 32 bytes");
        // let s_array = <[u8; 32]>::try_from(&SIG2[32..]).expect("should be 32 bytes");

        // let r = Point::lift_x(&r_array).unwrap().to_even_y();
        // let s = Scalar::from_slice(&s_array);
        // let signature = Signature {
        //     r,
        //     s: MaybeScalar::from(s.unwrap()).unwrap().into(),
        // };

        // assert!(schnorr_verify(public_key, signature, MSG2));

        // let public_key = Point::from_slice(PK3).unwrap();
        // let r_array = <[u8; 32]>::try_from(&SIG3[0..32]).expect("should be 32 bytes");
        // let s_array = <[u8; 32]>::try_from(&SIG3[32..]).expect("should be 32 bytes");

        // let r = Point::lift_x(&r_array).unwrap().to_even_y();
        // let s = Scalar::from_slice(&s_array);
        // let signature = Signature::from_bytes(SIG3);
        // let signature = Signature {
        //     r,
        //     s: MaybeScalar::from(s.unwrap()).unwrap().into(),
        // };

        // /* Test vector 6: R.y is not a quadratic residue */
        // assert!(!schnorr_verify(public_key, signature, MSG3));
    }
}
pub const PK1: &[u8; 33] = &[
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];
pub const MSG1: &[u8; 32] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub const SIG1: &[u8; 64] = &[
    0x78, 0x7a, 0x84, 0x8e, 0x71, 0x04, 0x3d, 0x28, 0x0c, 0x50, 0x47, 0x0e, 0x8e, 0x15, 0x32, 0xb2,
    0xdd, 0x5d, 0x20, 0xee, 0x91, 0x2a, 0x45, 0xdb, 0xdd, 0x2b, 0xd1, 0xdf, 0xbf, 0x18, 0x7e, 0xf6,
    0x70, 0x31, 0xa9, 0x88, 0x31, 0x85, 0x9d, 0xc3, 0x4d, 0xff, 0xee, 0xdd, 0xa8, 0x68, 0x31, 0x84,
    0x2c, 0xcd, 0x00, 0x79, 0xe1, 0xf9, 0x2a, 0xf1, 0x77, 0xf7, 0xf2, 0x2c, 0xc1, 0xdc, 0xed, 0x05,
];

pub const PK2: &[u8; 33] = &[
    0x02, 0xdf, 0xf1, 0xd7, 0x7f, 0x2a, 0x67, 0x1c, 0x5f, 0x36, 0x18, 0x37, 0x26, 0xdb, 0x23, 0x41,
    0xbe, 0x58, 0xfe, 0xae, 0x1d, 0xa2, 0xde, 0xce, 0xd8, 0x43, 0x24, 0x0f, 0x7b, 0x50, 0x2b, 0xa6,
    0x59,
];
pub const MSG2: &[u8; 32] = &[
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
];
pub const SIG2: &[u8; 64] = &[
    0x2a, 0x29, 0x8d, 0xac, 0xae, 0x57, 0x39, 0x5a, 0x15, 0xd0, 0x79, 0x5d, 0xdb, 0xfd, 0x1d, 0xcb,
    0x56, 0x4d, 0xa8, 0x2b, 0x0f, 0x26, 0x9b, 0xc7, 0x0a, 0x74, 0xf8, 0x22, 0x04, 0x29, 0xba, 0x1d,
    0x1e, 0x51, 0xa2, 0x2c, 0xce, 0xc3, 0x55, 0x99, 0xb8, 0xf2, 0x66, 0x91, 0x22, 0x81, 0xf8, 0x36,
    0x5f, 0xfc, 0x2d, 0x03, 0x5a, 0x23, 0x04, 0x34, 0xa1, 0xa6, 0x4d, 0xc5, 0x9f, 0x70, 0x13, 0xfd,
];

pub const PK3: &[u8; 33] = &[
    0x02, 0xdf, 0xf1, 0xd7, 0x7f, 0x2a, 0x67, 0x1c, 0x5f, 0x36, 0x18, 0x37, 0x26, 0xdb, 0x23, 0x41,
    0xbe, 0x58, 0xfe, 0xae, 0x1d, 0xa2, 0xde, 0xce, 0xd8, 0x43, 0x24, 0x0f, 0x7b, 0x50, 0x2b, 0xa6,
    0x59,
];
pub const MSG3: &[u8; 32] = &[
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
];
pub const SIG3: &[u8; 64] = &[
    0x2a, 0x29, 0x8d, 0xac, 0xae, 0x57, 0x39, 0x5a, 0x15, 0xd0, 0x79, 0x5d, 0xdb, 0xfd, 0x1d, 0xcb,
    0x56, 0x4d, 0xa8, 0x2b, 0x0f, 0x26, 0x9b, 0xc7, 0x0a, 0x74, 0xf8, 0x22, 0x04, 0x29, 0xba, 0x1d,
    0xfa, 0x16, 0xae, 0xe0, 0x66, 0x09, 0x28, 0x0a, 0x19, 0xb6, 0x7a, 0x24, 0xe1, 0x97, 0x7e, 0x46,
    0x97, 0x71, 0x2b, 0x5f, 0xd2, 0x94, 0x39, 0x14, 0xec, 0xd5, 0xf7, 0x30, 0x90, 0x1b, 0x4a, 0xb7,
];
