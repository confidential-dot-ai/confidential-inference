//! The gateway's usage reporter key.
//!
//! Confidential Cloud records the requests a reporter reports only from a
//! TLS client whose certificate carries a key it has bound to that reporter.
//! The gateway derives that Ed25519 key from its CDS secret, a value CDS
//! generates on the first ask and releases only to pods that attest as the
//! gateway's entry. So every replica holds the same key, and nothing outside
//! an attested gateway pod ever does. An operator binds the public key the
//! gateway serves at `/usage-reporter-key`, read through the attested channel.
//!
//! The certificate is self-signed: Confidential Cloud reads only its key,
//! and the TLS handshake shows the gateway holds it.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The derivation label of the reporter key. A new label gives a new key,
/// which an operator binds before the gateway that holds it reports.
const KEY_CONTEXT: &[u8] = b"confidential.ai/gateway-usage-reporter-key/v1";
/// The fewest bytes of secret the key is derived from. CDS generates 32.
pub const MINIMUM_SECRET_BYTES: usize = 32;
/// PKCS #8 v1 of an Ed25519 seed (RFC 8410), before the 32 seed bytes.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// `SubjectPublicKeyInfo` of an Ed25519 key (RFC 8410), before its 32 bytes.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The reporter key and its self-signed certificate.
pub struct ReporterKey {
    identity_pem: String,
    public_key_pem: String,
}

impl ReporterKey {
    /// Derive the key from the gateway's CDS secret.
    ///
    /// # Errors
    ///
    /// Returns an error for a secret shorter than [`MINIMUM_SECRET_BYTES`],
    /// or a certificate that fails to build.
    pub fn from_secret(secret: &[u8]) -> Result<Self, String> {
        if secret.len() < MINIMUM_SECRET_BYTES {
            return Err(format!(
                "the gateway secret holds {} bytes; the reporter key needs at least {MINIMUM_SECRET_BYTES}",
                secret.len()
            ));
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts a key of any length"));
        mac.update(KEY_CONTEXT);
        let seed: [u8; 32] = mac.finalize().into_bytes().into();
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();

        let pkcs8 = [PKCS8_PREFIX.as_slice(), seed.as_slice()].concat();
        let key_pair = rcgen::KeyPair::try_from(pkcs8.as_slice())
            .map_err(|_| "the reporter key failed to load")?;
        let certificate = rcgen::CertificateParams::new(vec!["usage-reporter".to_owned()])
            .and_then(|params| params.self_signed(&key_pair))
            .map_err(|_| "the reporter certificate failed to build")?;
        let spki = [SPKI_PREFIX.as_slice(), public.as_bytes().as_slice()].concat();
        Ok(Self {
            identity_pem: format!("{}{}", certificate.pem(), key_pair.serialize_pem()),
            public_key_pem: pem::encode(&pem::Pem::new("PUBLIC KEY", spki)),
        })
    }

    /// The certificate and its private key, in PEM, for the TLS client.
    #[must_use]
    pub fn identity_pem(&self) -> &str {
        &self.identity_pem
    }

    /// The public key, a PEM `PUBLIC KEY`, as the Cloud seed binds it.
    #[must_use]
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn one_secret_gives_one_key_and_its_certificate_carries_it() {
        let first = ReporterKey::from_secret(&[7; 32]).unwrap();
        let again = ReporterKey::from_secret(&[7; 32]).unwrap();
        let other = ReporterKey::from_secret(&[8; 32]).unwrap();
        assert_eq!(first.public_key_pem(), again.public_key_pem());
        assert_ne!(first.public_key_pem(), other.public_key_pem());

        let spki = pem::parse(first.public_key_pem()).unwrap();
        assert_eq!(spki.tag(), "PUBLIC KEY");
        let certificate = pem::parse_many(first.identity_pem()).unwrap();
        assert_eq!(certificate[0].tag(), "CERTIFICATE");
        assert_eq!(certificate[1].tag(), "PRIVATE KEY");
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate[0].contents()).unwrap();
        assert_eq!(parsed.public_key().raw, spki.contents());
    }

    #[test]
    fn a_short_secret_is_refused() {
        assert!(ReporterKey::from_secret(&[7; 31]).is_err());
    }
}
