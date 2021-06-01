use regex::Regex;
use ring::rand;
use ring::signature::{self};
use rustc_serialize::base64::FromBase64;
use simple_asn1::ASN1Block;
use simple_x509::*;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use std::io::Read;
use std::str;

const REGEX: &'static str = r"(-----BEGIN .*-----\n)((?:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)*\n)+)(-----END .*-----)";

fn read_file(f: &str) -> std::io::Result<Vec<u8>> {
    let mut fd = File::open(f)?;
    let mut data = Vec::new();
    let _amt = fd.read_to_end(&mut data)?;

    Ok(data)
}

fn write_file(f: &str, data: &Vec<u8>) -> std::io::Result<()> {
    let mut buffer = BufWriter::new(File::create(f)?);
    buffer.write_all(data)?;
    buffer.flush()?;

    Ok(())
}

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

fn get_key_from_pub_key(pub_key: &Vec<u8>) -> Option<Vec<u8>> {
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
    let k = get_key_from_pub_key(pub_key)?;
    let key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &k);
    match key.verify(data, sign) {
        Ok(_) => Some(true),
        Err(_) => Some(false),
    }
}

fn ec_verify_fn(pub_key: &Vec<u8>, data: &Vec<u8>, sign: &Vec<u8>) -> Option<bool> {
    let k = get_key_from_pub_key(pub_key)?;
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
    let pub_rsa_n: Vec<u8> = vec![
        0x00, 0xc4, 0x12, 0x74, 0x10, 0xe3, 0xd3, 0x37, 0x20, 0x3a, 0xe7, 0xfd, 0xf3, 0x3e, 0x1f,
        0x39, 0xd5, 0x3a, 0x02, 0xba, 0x9d, 0xf2, 0xcf, 0xec, 0xfe, 0x31, 0x79, 0x86, 0x09, 0x21,
        0xf9, 0xce, 0xe1, 0xee, 0x8e, 0xb0, 0x65, 0x1c, 0xe5, 0xf5, 0x5d, 0xdb, 0xc5, 0x9e, 0x40,
        0x06, 0xc4, 0x3b, 0xc9, 0x90, 0x45, 0xbd, 0xee, 0x70, 0xde, 0xb3, 0x36, 0x49, 0xee, 0xa9,
        0x72, 0xf0, 0xcb, 0x39, 0x6e, 0x43, 0xd9, 0xd0, 0xf1, 0x3c, 0xfd, 0x01, 0x4c, 0xb7, 0xef,
        0xcd, 0x1d, 0xb1, 0x59, 0x4d, 0xa5, 0xa0, 0x3e, 0x23, 0x5f, 0x4c, 0x7b, 0x6c, 0xd5, 0xbc,
        0xa3, 0xd3, 0x9b, 0x83, 0xa0, 0xb8, 0xe1, 0x57, 0x06, 0xd3, 0x2c, 0x08, 0xb0, 0x74, 0x1d,
        0xfb, 0x91, 0x63, 0xb2, 0x24, 0x60, 0xd0, 0x5a, 0x34, 0x11, 0xd4, 0x1a, 0x9d, 0xa7, 0x4e,
        0xd3, 0x99, 0x82, 0x14, 0x5d, 0x72, 0xef, 0xd1, 0x0e, 0x15, 0xcd, 0x21, 0xfc, 0x2b, 0x3d,
        0xb3, 0x1d, 0x67, 0xf0, 0x06, 0xcc, 0x48, 0x0e, 0xeb, 0xab, 0x9f, 0x0e, 0x5c, 0xd9, 0xd2,
        0x8d, 0xb2, 0x11, 0x8d, 0x63, 0x0d, 0x05, 0xdb, 0x6f, 0xb1, 0xa1, 0xa1, 0xf6, 0xe8, 0xb9,
        0x3d, 0x04, 0x9d, 0x34, 0xe1, 0x77, 0x44, 0xde, 0xc3, 0xb2, 0x89, 0x89, 0x39, 0x7e, 0x34,
        0xc2, 0xcb, 0xe7, 0xa0, 0x45, 0x4f, 0x60, 0x5a, 0x25, 0x13, 0x04, 0xf2, 0x93, 0x8b, 0xa8,
        0xba, 0x1e, 0x74, 0xb4, 0xcd, 0xe6, 0x5e, 0xdd, 0x84, 0x05, 0xb3, 0x7e, 0xb2, 0x67, 0xc2,
        0xce, 0x6d, 0x3e, 0x4d, 0xb9, 0xbc, 0x7d, 0x4f, 0x32, 0xc0, 0xe8, 0x82, 0x34, 0x61, 0x06,
        0x8d, 0xa6, 0x96, 0x2f, 0x52, 0xb9, 0xb5, 0x7c, 0x86, 0xf1, 0xd8, 0x8e, 0xd0, 0x3d, 0x66,
        0x16, 0x1c, 0x5a, 0xc1, 0xc5, 0x8e, 0x05, 0xe4, 0xfd, 0x47, 0xcc, 0xf6, 0x2a, 0xe3, 0x52,
        0x6b, 0x23,
    ];

    let country = "AU";
    let state = "Some-State";
    let organization = "Internet Widgits Pty Ltd";

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
        .pub_key_rsa(
            vec![1, 2, 840, 113549, 1, 1, 1], /* rsaEncryption (PKCS #1) */
            pub_rsa_n,
            65537,
        )
        .sign_oid(vec![1, 2, 840, 113549, 1, 1, 11]) /* sha256WithRSAEncryption (PKCS #1) */
        .build();

    let sign_key = read_file("tests/data/rsa.pkcs8").unwrap_or_else(|_| panic!("File not found"));
    let cert = match x.sign(rsa_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = write_file("tests/data/ca_rsa.der", &der).map_err(|e| e.kind());
    assert_eq!(err, Ok(()));
}

#[test]
fn x509_rsa_pub_key_test() {
    let country = "AU";
    let state = "Some-State";
    let organization = "Internet Widgits Pty Ltd";
    let pub_key = read_file("tests/data/rsa_pub.der").unwrap_or_else(|_| panic!("File not found"));

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

    let sign_key = read_file("tests/data/rsa.pkcs8").unwrap_or_else(|_| panic!("File not found"));
    let cert = match x.sign(rsa_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = write_file("tests/data/ca_rsa_pd.der", &der).map_err(|e| e.kind());
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

    let sign_key = read_file("tests/data/ec.pkcs8").unwrap_or_else(|_| panic!("File not found"));
    let cert = match x.sign(ec_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = write_file("tests/data/ca_ec.der", &der).map_err(|e| e.kind());
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

    let sign_key = read_file("tests/data/ec.pkcs8").unwrap_or_else(|_| panic!("File not found"));
    let cert = match x.sign(ec_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("sign() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x509_enc() failed"),
    };

    let err = write_file("tests/data/ca_extension_raw.der", &der).map_err(|e| e.kind());
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

    let sign_key = read_file("tests/data/ec.pkcs8").unwrap_or_else(|_| panic!("File not found"));
    let cert = match x.sign(ec_sign_fn, &sign_key) {
        Some(c) => c,
        None => panic!("build() failed"),
    };

    let der = match cert.x509_enc() {
        Some(d) => d,
        None => panic!("x.x509_enc() failed"),
    };

    let err = write_file("tests/data/ca_key_usage.der", &der).map_err(|e| e.kind());
    assert_eq!(err, Ok(()));
}

#[test]
fn x509_rsa_deserialize() {
    let der = read_file("tests/data/cert_rsa.der").unwrap_or_else(|_| panic!("File not found"));
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
    let der = read_file("tests/data/cert_ec.der").unwrap_or_else(|_| panic!("File not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let der2 = x
        .x509_enc()
        .unwrap_or_else(|| panic!("Failed to serialize"));
    assert_eq!(der, der2);
}

#[test]
fn x509_decoding_encoding() {
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
        let pem = match read_file(&p) {
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
    let der = read_file("tests/data/cert_rsa.der").unwrap_or_else(|_| panic!("File not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let pub_key = read_file("tests/data/rsa_pub.der").unwrap_or_else(|_| panic!("File not found"));
    let pub_key2 = x
        .pub_key()
        .unwrap_or_else(|| panic!("Failed to get Public Key"));

    assert_eq!(x.verify(rsa_verify_fn, &pub_key), Some(true));
    assert_eq!(x.verify(rsa_verify_fn, &pub_key2), Some(true));
}

#[test]
fn x509_ec_verify() {
    let der = read_file("tests/data/cert_ec.der").unwrap_or_else(|_| panic!("File not found"));
    let x = der
        .x509_dec()
        .unwrap_or_else(|| panic!("Failed to deserialize"));

    let pub_key = x
        .pub_key()
        .unwrap_or_else(|| panic!("Failed to get Public Key"));

    assert_eq!(x.verify(ec_verify_fn, &pub_key), Some(true));
}
