use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::error::DemoError;

use openssl;
use openssl::bn::BigNum;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::X509;

#[derive(Clone)]
pub struct Identity {
    pub private_key: Arc<PKey<Private>>,
    pub certificate: X509,
    pub fingerprint: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Identity, DemoError> {
        // Generate private key
        let mut group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        group.set_asn1_flag(Asn1Flag::NAMED_CURVE);
        let eckey = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(eckey)?;

        // Generate certificate
        let mut builder = X509::builder()?;
        // Serial number -- random 64-bit value
        use rand::RngCore;
        let mut serial: Vec<u8> = vec![0; 8];
        ::rand::thread_rng().fill_bytes(&mut serial);
        let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        // Validity: Mimic the Chrome behavior of a not-before time of one day ago, and a not-after
        // time of one month from now.
        let s = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            - Duration::from_secs(24 * 60 * 60);
        let start = openssl::asn1::Asn1Time::from_unix(i64::try_from(s.as_secs()).unwrap())?;
        let stop = openssl::asn1::Asn1Time::days_from_now(30)?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&stop)?;
        // Set public key
        builder.set_pubkey(&pkey)?;
        // Set subject name
        let mut name = openssl::x509::X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "WebRTC")?;
        let name = name.build();
        builder.set_subject_name(&name)?;
        // Set the issuer to the same as the subject
        builder.set_issuer_name(&name)?;
        // Sign the certificate with SHA-256
        builder.sign(&pkey, MessageDigest::sha256())?;

        // Build certificate
        let certificate = builder.build();

        // SHA-256 hash the DER encoding of the certificate to determine the fingerprint.
        let fingerprint = ::openssl::sha::sha256(&certificate.to_der()?).to_vec();

        Ok(Identity {
            private_key: Arc::new(pkey),
            certificate,
            fingerprint,
        })
    }
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).unwrap();
    signer.update(data).unwrap();
    signer.sign_to_vec().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let _identity = Identity::generate().unwrap();
        // TODO test signing & verifying
    }
}
