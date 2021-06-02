//! # Overview
//!
//! This is a simple library for creating and parsing X509 certificates.
//!
//! A Library featuring:
//!
//! -   Build X509 certificates
//! -   Encode certificates to DER format
//! -   Signing with external crypto function
//! -   Decoding of X509 certificates from DER format
//! -   Verifying with external crypto function
//! -   Encoding/decoding operations for frequently using extensions
//!
//! ## Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! simple_x509 = "0.2.0"
//! ```
//!
//! ## Simple X509
//!
//! Create and verify self-signed CA certificate
//!
//! ```no_run
//! use simple_x509::*;
//!
//! fn sign_fn(data: &Vec<u8>, sign_key: &Vec<u8>) -> Option<Vec<u8>> {
//!
//!     // Signing implementation ...
//!
//!     Some(Vec::new())
//! }
//!
//! fn verify_fn(pub_key: &Vec<u8>, data: &Vec<u8>, sign: &Vec<u8>) -> Option<bool> {
//!
//!     // Verify implementation ...
//!
//!     Some(true)
//! }
//!
//! fn main() {
//!     let country = "AU";
//!     let state = "Some-State";
//!     let organization = "Internet Widgits Pty Ltd";
//!
//!     // Load Public Key
//!     let pub_key = std::fs::read("rsa_pub.der").unwrap();
//!
//!     // Build X509 structure
//!     let x = X509Builder::new(vec![0xf2, 0xf9, 0xd8, 0x03, 0xd7, 0xb7, 0xd7, 0x34]) /* SerialNumber */
//!         .version(2)
//!         .issuer_prstr(vec![2, 5, 4, 6], country) /* countryName */
//!         .issuer_utf8(vec![2, 5, 4, 8], state) /* stateOrProvinceName */
//!         .issuer_utf8(vec![2, 5, 4, 10], organization) /* organizationName */
//!         .subject_prstr(vec![2, 5, 4, 6], country) /* countryName */
//!         .subject_utf8(vec![2, 5, 4, 8], state) /* stateOrProvinceName */
//!         .subject_utf8(vec![2, 5, 4, 10], organization) /* organizationName */
//!         .not_before_utc(1_619_014_703)
//!         .not_after_utc(1_650_550_703)
//!         .pub_key_der(&pub_key)
//!         .sign_oid(vec![1, 2, 840, 113549, 1, 1, 11]) /* sha256WithRSAEncryption (PKCS #1) */
//!         .build();
//!
//!     // Load Signing Key
//!     let sign_key = std::fs::read("rsa.pkcs8").unwrap();
//!
//!     // Signing a certificate with external function
//!     let cert = x.sign(sign_fn, &sign_key).unwrap_or_else(|| panic!("Signing failed"));
//!
//!     // Encode to DER format
//!     let der = cert.x509_enc().unwrap_or_else(|| panic!("x509_enc() failed"));
//!
//!     // Decode
//!     let x2 = der.x509_dec().unwrap_or_else(|| panic!("Failed to deserialize"));
//!
//!     // Getting Public Key in DER format from certificate
//!     let pub_key2 = x2.pub_key().unwrap_or_else(|| panic!("Failed to get Public Key"));
//!
//!     // Verify signature with external function
//!     let res = x2.verify(verify_fn, &pub_key2);
//! }
//! ```

pub mod ext;
pub mod x509;

pub use ext::*;
pub use x509::*;
