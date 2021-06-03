use regex::Regex;
use ring::rand;
use ring::signature::{self};
use rustc_serialize::base64::FromBase64;
use simple_asn1::ASN1Block;
use simple_x509::*;
use std::fs;
use std::str;

const REGEX: &'static str = r"(-----BEGIN .*-----\n)((?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\n)+)(-----END .*-----)";

fn rsa_sign_fn(data: &Vec<u8>, sign_key: &Vec<u8>) -> Option<Vec<u8>> {
    let key = signature::RsaKeyPair::from_pkcs8(sign_key).ok()?;
    let mut sig = vec![0; key.public_modulus_len()];

    let rng = rand::SystemRandom::new();

    key.sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut sig)
        .ok()?;

    Some(sig)
}

fn ec_sign_fn(data: &Vec<u8>, sign_key: &Vec<u8>) -> Option<Vec<u8>> {
    let key =
        signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, sign_key)
            .ok()?;
    let rng = rand::SystemRandom::new();
    let sig = key.sign(&rng, data).ok()?;

    Some(sig.as_ref().to_vec())
}

fn ring_key_from_pub_key(pub_key: &Vec<u8>) -> Option<Vec<u8>> {
    let asn = simple_asn1::from_der(pub_key).ok()?;
    let bs = match asn.get(0)? {
        ASN1Block::Sequence(_, s) => s.get(1)?,
        _ => return None,
    };
    let key = match bs {
        ASN1Block::BitString(_, _, k) => k,
        _ => return None,
    };

    Some(key.to_vec())
}

fn rsa_verify_fn(pub_key: &Vec<u8>, data: &Vec<u8>, sign: &Vec<u8>) -> Option<bool> {
    let k = ring_key_from_pub_key(pub_key)?;
    let key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &k);
    match key.verify(data, sign) {
        Ok(_) => Some(true),
        Err(_) => Some(false),
    }
}

fn ec_verify_fn(pub_key: &Vec<u8>, data: &Vec<u8>, sign: &Vec<u8>) -> Option<bool> {
    let k = ring_key_from_pub_key(pub_key)?;
    let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &k);
    match key.verify(data, sign) {
        Ok(_) => Some(true),
        Err(_) => Some(false),
    }
}

fn pem_to_der(f: &str) -> Option<Vec<u8>> {
    let r = Regex::new(REGEX).ok()?;
    let v = r.replace(f, "$2");
    let b = v.replace("\n", "");
    b.from_base64().ok()
}

#[test]
fn x509_rsa_root_test() {
    let country = "AU";
    let state = "Some-State";
    let organization = "Internet Widgits Pty Ltd";
    let pub_key = std::fs::read("tests/data/rsa_pub.der").unwrap_or_else(|_| panic!("Not found"));

    let x = X509Builder::new(vec![0xf2, 0xf9, 0xd8, 0x03, 0xd7, 0xb7, 0xd7, 0x34])
        .version(2)
        .issuer_prstr(vec![2, 5, 4, 6], country) /* countryName */
        .issuer_utf8(vec![2, 5, 4, 8], state) /* stateOrProvinceName */
        .issuer_utf8(vec![2, 5, 4, 10], organization) /* organizationName */
        .subject_prstr(vec![2, 5, 4, 6], country) /* countryName */
        .subject_utf8(vec![2, 5, 4, 8], state) /* stateOrProvinceName */
        .subject_utf8(vec![2, 5, 4, 10], organization) /* organizationName */
        .not_before_utc(1_619_014_703)
        .not_after_utc(1_650_550_703)
        .pub_key_der(&pub_key)
        .sign_oid(vec![1, 2, 840, 113549, 1, 1, 11]) /* sha256WithRSAEncryption (PKCS #1) */
        .build();

    let sign_key = std::fs::read("tests/data/rsa.pkcs8").unwrap_or_else(|_| panic!("Not found"));
    let cert = match x.sign(rsa_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = std::fs::write("tests/data/ca_rsa.der", &der).map_err(|e| e.kind());
    assert_eq!(err, Ok(()));

    let x2 = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let pub_key2 = x2
        .pub_key()
        .unwrap_or_else(|| panic!("Failed to get pub_key"));

    assert_eq!(pub_key, pub_key2);
}

#[test]
fn x509_ec_root_test() {
    let pub_ec_key: Vec<u8> = vec![
        0x04, 0xFE, 0x0B, 0x0F, 0x80, 0x27, 0x39, 0xCC, 0x47, 0xD7, 0x86, 0xEE, 0x0D, 0xAE, 0xE5,
        0x67, 0x77, 0x14, 0xBC, 0xBE, 0xAF, 0x9E, 0x90, 0xA1, 0x8C, 0xF3, 0x5C, 0xC8, 0x57, 0x9F,
        0xFA, 0xB3, 0x9D, 0xEE, 0xD8, 0x55, 0x82, 0xCA, 0x3B, 0x68, 0x72, 0x14, 0xE5, 0xAE, 0x42,
        0xBE, 0x0D, 0xAD, 0x5B, 0xDA, 0xAC, 0xEB, 0x0A, 0x5D, 0xDA, 0x01, 0x5D, 0xF6, 0xD4, 0x73,
        0x2A, 0xFB, 0x9E, 0xAB, 0x10,
    ];

    let country = "AU";
    let state = "Some-State";
    let organization = "Internet Widgits Pty Ltd";

    let x = X509Builder::new(vec![0xf2, 0xf9, 0xd8, 0x03, 0xd7, 0xb7, 0xd7, 0x34])
        .version(2)
        .issuer_prstr(vec![ 2, 5, 4, 6 ], country) /* countryName */
        .issuer_utf8(vec![ 2, 5, 4, 8 ], state) /* stateOrProvinceName */
        .issuer_utf8(vec![ 2, 5, 4, 10 ], organization) /* organizationName */
        .subject_prstr(vec![ 2, 5, 4, 6 ], country) /* countryName */
        .subject_utf8(vec![ 2, 5, 4, 8 ], state) /* stateOrProvinceName */
        .subject_utf8(vec![ 2, 5, 4, 10 ], organization) /* organizationName */
        .not_before_utc(1_619_014_703)
        .not_after_utc(1_650_550_703)
        .pub_key_ec(
            vec![ 1, 2, 840, 10045, 2, 1 ], /* ecPublicKey (ANSI X9.62 public key type) */
            pub_ec_key,
            vec![ 1, 2, 840, 10045, 3, 1, 7 ], /* prime256v1 (ANSI X9.62 named elliptic curve) */
        )
        .sign_oid(vec![ 1, 2, 840, 10045, 4, 3, 2 ]) /* ecdsaWithSHA256 (ANSI X9.62 ECDSA with SHA256) */
        .build();

    let sign_key = std::fs::read("tests/data/ec.pkcs8").unwrap_or_else(|_| panic!("Not found"));
    let cert = match x.sign(ec_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = std::fs::write("tests/data/ca_ec.der", &der).map_err(|e| e.kind());
    assert_eq!(err, Ok(()));
}

#[test]
fn x509_extension_raw() {
    let pub_ec_key: Vec<u8> = vec![
        0x04, 0xFE, 0x0B, 0x0F, 0x80, 0x27, 0x39, 0xCC, 0x47, 0xD7, 0x86, 0xEE, 0x0D, 0xAE, 0xE5,
        0x67, 0x77, 0x14, 0xBC, 0xBE, 0xAF, 0x9E, 0x90, 0xA1, 0x8C, 0xF3, 0x5C, 0xC8, 0x57, 0x9F,
        0xFA, 0xB3, 0x9D, 0xEE, 0xD8, 0x55, 0x82, 0xCA, 0x3B, 0x68, 0x72, 0x14, 0xE5, 0xAE, 0x42,
        0xBE, 0x0D, 0xAD, 0x5B, 0xDA, 0xAC, 0xEB, 0x0A, 0x5D, 0xDA, 0x01, 0x5D, 0xF6, 0xD4, 0x73,
        0x2A, 0xFB, 0x9E, 0xAB, 0x10,
    ];

    let common_name = "Name name";

    let x = X509Builder::new(vec![0xf2, 0xf9, 0xd8, 0x03, 0xd7, 0xb7, 0xd7, 0x34])
        .issuer_utf8(vec![ 2, 5, 4, 3 ], common_name) /* organizationName */
        .subject_utf8(vec![ 2, 5, 4, 3 ], common_name) /* organizationName */
        .not_before_utc(1_619_014_703)
        .not_after_utc(1_650_550_703)
        .pub_key_ec(
            vec![ 1, 2, 840, 10045, 2, 1 ], /* ecPublicKey (ANSI X9.62 public key type) */
            pub_ec_key,
            vec![ 1, 2, 840, 10045, 3, 1, 7 ], /* prime256v1 (ANSI X9.62 named elliptic curve) */
        )
        .ext_raw(
            vec![ 2, 5, 29, 15 ], /* keyUsage (X.509 extension) */
            true,
            vec![ 0x03, 0x02, 0x04, 0xB0 ],
        )
        .sign_oid(vec![ 1, 2, 840, 10045, 4, 3, 2 ]) /* ecdsaWithSHA256 (ANSI X9.62 ECDSA with SHA256) */
        .build();

    let sign_key = std::fs::read("tests/data/ec.pkcs8").unwrap_or_else(|_| panic!("Not found"));
    let cert = match x.sign(ec_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = std::fs::write("tests/data/ca_extension_raw.der", &der).map_err(|e| e.kind());
    assert_eq!(err, Ok(()));
}

#[test]
fn x509_key_usage_extension() {
    let pub_ec_key: Vec<u8> = vec![
        0x04, 0xFE, 0x0B, 0x0F, 0x80, 0x27, 0x39, 0xCC, 0x47, 0xD7, 0x86, 0xEE, 0x0D, 0xAE, 0xE5,
        0x67, 0x77, 0x14, 0xBC, 0xBE, 0xAF, 0x9E, 0x90, 0xA1, 0x8C, 0xF3, 0x5C, 0xC8, 0x57, 0x9F,
        0xFA, 0xB3, 0x9D, 0xEE, 0xD8, 0x55, 0x82, 0xCA, 0x3B, 0x68, 0x72, 0x14, 0xE5, 0xAE, 0x42,
        0xBE, 0x0D, 0xAD, 0x5B, 0xDA, 0xAC, 0xEB, 0x0A, 0x5D, 0xDA, 0x01, 0x5D, 0xF6, 0xD4, 0x73,
        0x2A, 0xFB, 0x9E, 0xAB, 0x10,
    ];

    let common_name = "Name name";

    let key_usage = X509ExtBuilder::new()
        .key_usage(vec![
            X509KeyUsage::DigitalSignature,
            X509KeyUsage::KeyEncipherment,
            X509KeyUsage::DataEncipherment,
        ])
        .build();

    let x = X509Builder::new(vec![0xf2, 0xf9, 0xd8, 0x03, 0xd7, 0xb7, 0xd7, 0x34])
        .issuer_utf8(vec![ 2, 5, 4, 3 ], common_name) /* commonName */
        .subject_utf8(vec![ 2, 5, 4, 3 ], common_name) /* commonName */
        .not_before_utc(1_619_014_703)
        .not_after_utc(1_650_550_703)
        .pub_key_ec(
            vec![ 1, 2, 840, 10045, 2, 1 ], /* ecPublicKey (ANSI X9.62 public key type) */
            pub_ec_key,
            vec![ 1, 2, 840, 10045, 3, 1, 7 ], /* prime256v1 (ANSI X9.62 named elliptic curve) */
        )
        .ext(key_usage)
        .sign_oid(vec![ 1, 2, 840, 10045, 4, 3, 2 ]) /* ecdsaWithSHA256 (ANSI X9.62 ECDSA with SHA256) */
        .build();

    let sign_key = std::fs::read("tests/data/ec.pkcs8").unwrap_or_else(|_| panic!("Not found"));
    let cert = match x.sign(ec_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("build() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x.x509_enc() failed"),
    };

    let err = std::fs::write("tests/data/ca_key_usage.der", &der).map_err(|e| e.kind());
    assert_eq!(err, Ok(()));
}

#[test]
fn x509_rsa_deserialize() {
    let der = std::fs::read("tests/data/cert_rsa.der").unwrap_or_else(|_| panic!("Not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let der2 = x
        .x509_enc()
        .unwrap_or_else(|| panic!("Failed to serialize"));
    assert_eq!(der, der2);
}

#[test]
fn x509_ec_deserialize() {
    let der = std::fs::read("tests/data/cert_ec.der").unwrap_or_else(|_| panic!("Not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let der2 = x
        .x509_enc()
        .unwrap_or_else(|| panic!("Failed to serialize"));
    assert_eq!(der, der2);
}

#[test]
fn x509_multiple_dec_enc() {
    let ret = fs::read_dir("/etc/ssl/certs/");
    let paths = match ret {
        Ok(p) => p,
        Err(_) => return, /* skip test */
    };

    let mut counter = 0;

    for path in paths {
        let p = match path {
            Ok(pt) => pt.path().display().to_string(),
            Err(_) => continue,
        };
        let pem = match std::fs::read(&p) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let st = match str::from_utf8(&pem) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let der = match pem_to_der(st) {
            Some(d) => d,
            None => continue,
        };

        let x = match der.x509_dec() {
            Some(x) => x,
            None => {
                println!("Failed to deserialize: {}", p);
                continue;
            }
        };

        let der2 = x
            .x509_enc()
            .unwrap_or_else(|| panic!("Failed to serialize: {}", p));

        assert_eq!(der, der2);
        counter += 1;
    }

    println!("{} certificates are tested", counter);
}

#[test]
fn x509_rsa_verify() {
    let der = std::fs::read("tests/data/cert_rsa.der").unwrap_or_else(|_| panic!("Not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let pub_key = std::fs::read("tests/data/rsa_pub.der").unwrap_or_else(|_| panic!("Not found"));
    let pub_key2 = x
        .pub_key()
        .unwrap_or_else(|| panic!("Failed to get Public Key"));

    assert_eq!(x.verify(rsa_verify_fn, &pub_key), Some(true));
    assert_eq!(x.verify(rsa_verify_fn, &pub_key2), Some(true));
}

#[test]
fn x509_ec_verify() {
    let der = std::fs::read("tests/data/cert_ec.der").unwrap_or_else(|_| panic!("Not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let pub_key = x
        .pub_key()
        .unwrap_or_else(|| panic!("Failed to get Public Key"));

    assert_eq!(x.verify(ec_verify_fn, &pub_key), Some(true));
}

#[test]
fn x509_key_usage_decoding() {
    let der =
        std::fs::read("tests/data/cert_key_usage.der").unwrap_or_else(|_| panic!("Not found"));

    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let key_usage = x
        .ext
        .key_usage()
        .unwrap_or_else(|| panic!("KeyUsage extension is not found"));

    assert_eq!(
        key_usage,
        vec![
            X509KeyUsage::DigitalSignature,
            X509KeyUsage::KeyEncipherment,
            X509KeyUsage::DataEncipherment,
        ]
    );
}
