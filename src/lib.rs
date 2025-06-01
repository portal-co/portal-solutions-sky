#![no_std]

use sha3::{
    Digest,
    digest::generic_array::{ArrayLength, GenericArray},
};
use slh_dsa::{ParameterSet, Signature, VerifyingKey, signature::*};
pub fn sky<P: ParameterSet<SigLen: ArrayLength<u8>>>(
    a: &str,
    keys: impl Iterator<Item = VerifyingKey<P>> + Clone,
) -> impl Iterator<Item = (&str, VerifyingKey<P>)> + Clone {
    a.split("?")
        .flat_map(|a| a.split("&"))
        .filter_map(|a| a.strip_prefix("sky="))
        .filter_map(move |b| {
            let (sig, pay) = b.split_once("=")?;
            let (manifest, pay) = pay.split_once("=")?;
            let (u, q) = a.split_once("?")?;
            let mut hash = sha3::Sha3_256::new();
            hash.update(manifest);
            hash.update(&[0xff]);
            hash.update(pay);
            hash.update(&[0xff]);
            let manifest = match manifest.strip_prefix("nh-") {
                Some(a) => a,
                None => {
                    hash.update(u);
                    hash.update(&[0xff]);
                    manifest
                }
            };
            for s in q.split("&") {
                if let Some(a) = s.strip_prefix("sky=") {
                    if a.starts_with(sig) {
                        continue;
                    }
                }
                let Some((k, v)) = s.split_once("=") else {
                    continue;
                };
                let mut m = manifest.split(",");
                if m.any(|v| v == k) {
                    continue;
                }
                hash.update(k);
                hash.update(&[0xff]);
                hash.update(v);
                hash.update(&[0xff]);
            }

            let hash: [u8; 32] = hash.finalize().into();
            let mut g = GenericArray::<u8, P::SigLen>::default();

            hex::decode_to_slice(sig, &mut g).ok()?;

            let s = Signature::try_from(g.as_slice()).ok()?;
            for k in keys.clone() {
                if k.verify(&hash, &s).is_ok() {
                    return Some((pay, k));
                }
            }
            None
        })
}
