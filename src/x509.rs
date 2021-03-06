use crate::X509Ext;
use chrono::{DateTime, TimeZone, Utc};
use num_traits::cast::ToPrimitive;
use simple_asn1::{ASN1Block, ASN1Class, BigInt, BigUint, OID};
use std::convert::TryFrom;
use std::ops::Deref;

#[derive(Debug, PartialEq)]
pub struct OidStr {
    pub oid: Vec<u64>,
    pub data: String,
}

#[derive(Debug, PartialEq)]
pub enum X509Name {
    Utf8(OidStr),
    PrStr(OidStr),
    TtxStr(OidStr),
    Ia5Str(OidStr),
}

#[derive(Debug, PartialEq)]
pub enum X509Time {
    Utc(i64),
    Gen(i64),
}

#[derive(Debug, PartialEq)]
pub struct RsaPub {
    pub pub_oid: Vec<u64>,
    pub n: Vec<u8>,
    pub e: u32,
}

#[derive(Debug, PartialEq)]
pub struct EcPub {
    pub pub_oid: Vec<u64>,
    pub key: Vec<u8>,
    pub curve: Vec<u64>,
}

#[derive(Debug, PartialEq)]
pub enum PubKey {
    Rsa(RsaPub),
    Ec(EcPub),
}

#[derive(Debug, PartialEq)]
pub struct X509 {
    pub version: Option<u64>,
    pub sn: Vec<u8>,
    pub issuer: Vec<X509Name>,
    pub subject: Vec<X509Name>,
    pub not_before: Option<X509Time>,
    pub not_after: Option<X509Time>,
    pub pub_key: Option<PubKey>,
    pub ext: Vec<X509Ext>,
    pub sign_oid: Vec<u64>,
    pub sign: Vec<u8>,
}

fn serialize(a: &ASN1Block) -> Option<Vec<u8>> {
    match simple_asn1::to_der(a) {
        Ok(d) => Some(d),
        Err(_) => None,
    }
}

fn oid_new(id: &Vec<u64>) -> OID {
    let mut res = Vec::new();

    for i in 0..id.len() {
        res.push(BigUint::from(id[i]));
    }

    OID::new(res)
}

fn seq_oid_str(v: &OidStr) -> Vec<ASN1Block> {
    let mut vec = Vec::new();
    vec.push(ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)));
    vec.push(ASN1Block::PrintableString(1, String::from(&v.data)));

    let mut seq = Vec::new();
    seq.push(ASN1Block::Sequence(0, vec));

    seq
}

fn seq_oid_utf8(v: &OidStr) -> Vec<ASN1Block> {
    let mut vec = Vec::new();
    vec.push(ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)));
    vec.push(ASN1Block::UTF8String(1, String::from(&v.data)));

    let mut seq = Vec::new();
    seq.push(ASN1Block::Sequence(0, vec));

    seq
}

fn seq_oid_ttx(v: &OidStr) -> Vec<ASN1Block> {
    let mut vec = Vec::new();
    vec.push(ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)));
    vec.push(ASN1Block::TeletexString(1, String::from(&v.data)));

    let mut seq = Vec::new();
    seq.push(ASN1Block::Sequence(0, vec));

    seq
}

fn seq_oid_ia5(v: &OidStr) -> Vec<ASN1Block> {
    let mut vec = Vec::new();
    vec.push(ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)));
    vec.push(ASN1Block::IA5String(1, String::from(&v.data)));

    let mut seq = Vec::new();
    seq.push(ASN1Block::Sequence(0, vec));

    seq
}

fn x509_name(name: &Vec<X509Name>) -> Vec<ASN1Block> {
    let mut n = Vec::new();

    for i in 0..name.len() {
        match &name[i] {
            X509Name::Utf8(s) => n.push(ASN1Block::Set(0, seq_oid_utf8(s))),
            X509Name::PrStr(s) => n.push(ASN1Block::Set(0, seq_oid_str(s))),
            X509Name::TtxStr(s) => n.push(ASN1Block::Set(0, seq_oid_ttx(s))),
            X509Name::Ia5Str(s) => n.push(ASN1Block::Set(0, seq_oid_ia5(s))),
        }
    }

    n
}

fn validity_time(not_before: &X509Time, not_after: &X509Time) -> Vec<ASN1Block> {
    let mut v = Vec::new();

    match not_before {
        X509Time::Utc(nb) => v.push(ASN1Block::UTCTime(0, Utc.timestamp(*nb, 0))),
        X509Time::Gen(nb) => v.push(ASN1Block::GeneralizedTime(0, Utc.timestamp(*nb, 0))),
    }

    match not_after {
        X509Time::Utc(na) => v.push(ASN1Block::UTCTime(0, Utc.timestamp(*na, 0))),
        X509Time::Gen(na) => v.push(ASN1Block::GeneralizedTime(0, Utc.timestamp(*na, 0))),
    }

    v
}

fn version_explicit(val: u64) -> ASN1Block {
    ASN1Block::Explicit(
        ASN1Class::ContextSpecific,
        0,
        BigUint::from(0 as u32),
        Box::new(ASN1Block::Integer(0, BigInt::from(val))),
    )
}

fn extension_explicit(ext: Vec<ASN1Block>) -> ASN1Block {
    ASN1Block::Explicit(
        ASN1Class::ContextSpecific,
        0,
        BigUint::from(3 as u32),
        Box::new(ASN1Block::Sequence(0, ext)),
    )
}

fn x509_ext(e: &X509Ext) -> Vec<ASN1Block> {
    let mut ext = Vec::new();
    ext.push(ASN1Block::ObjectIdentifier(0, oid_new(&e.oid)));
    if e.critical {
        ext.push(ASN1Block::Boolean(0, true));
    }
    ext.push(ASN1Block::OctetString(0, e.data.clone()));

    ext
}

fn null_oid(oid: &Vec<u64>) -> Vec<ASN1Block> {
    let mut sa = Vec::new();
    sa.push(ASN1Block::ObjectIdentifier(0, oid_new(oid)));
    sa.push(ASN1Block::Null(0));

    sa
}

fn vec_oid(oid: &Vec<u64>) -> Vec<ASN1Block> {
    let mut sa = Vec::new();
    sa.push(ASN1Block::ObjectIdentifier(0, oid_new(oid)));

    sa
}

fn rsa_pub(rsa: &RsaPub) -> Option<Vec<ASN1Block>> {
    let mut r = Vec::new();
    r.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&rsa.n)));
    r.push(ASN1Block::Integer(0, BigInt::from(rsa.e)));

    let der = match simple_asn1::to_der(&ASN1Block::Sequence(0, r)) {
        Ok(d) => d,
        Err(_) => {
            println!("Failed: serialize RSA pubkey");
            return None;
        }
    };

    let mut ret = Vec::new();
    ret.push(ASN1Block::Sequence(0, null_oid(&rsa.pub_oid)));
    ret.push(ASN1Block::BitString(0, der.len() * 8, der));

    Some(ret)
}

fn ec_pub(ec: &EcPub) -> Vec<ASN1Block> {
    let mut e = Vec::new();
    e.push(ASN1Block::ObjectIdentifier(0, oid_new(&ec.pub_oid)));
    e.push(ASN1Block::ObjectIdentifier(0, oid_new(&ec.curve)));

    let mut ret = Vec::new();
    ret.push(ASN1Block::Sequence(0, e));
    ret.push(ASN1Block::BitString(0, ec.key.len() * 8, ec.key.clone()));

    ret
}

fn build_pub_key(pub_key: &Option<PubKey>) -> Option<Vec<ASN1Block>> {
    match pub_key {
        Some(PubKey::Rsa(ref rsa)) => rsa_pub(rsa),
        Some(PubKey::Ec(ref ec)) => Some(ec_pub(ec)),
        None => None,
    }
}

fn x509_body(x: &X509) -> Option<Vec<ASN1Block>> {
    let mut body = Vec::new();

    /* Version */
    if let Some(v) = x.version {
        body.push(version_explicit(v));
    }

    /* Serial Number */
    body.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&x.sn)));

    /* Signature Algorithm */
    match x.pub_key {
        Some(PubKey::Rsa(_)) => body.push(ASN1Block::Sequence(0, null_oid(&x.sign_oid))),
        Some(PubKey::Ec(_)) => body.push(ASN1Block::Sequence(0, vec_oid(&x.sign_oid))),
        None => {
            println!("Failed: no public key");
            return None;
        }
    }

    /* Issuer name */
    if x.issuer.len() > 0 {
        body.push(ASN1Block::Sequence(0, x509_name(&x.issuer)));
    } else {
        println!("Failed: no issuer name");
        return None;
    }

    /* Validity time */
    if x.not_before == None || x.not_after == None {
        println!("Failed: no validity time");
        return None;
    }

    let validity = validity_time(
        &x.not_before.as_ref().unwrap(),
        &x.not_after.as_ref().unwrap(),
    );
    body.push(ASN1Block::Sequence(0, validity));

    /* Subject name */
    if x.subject.len() > 0 {
        body.push(ASN1Block::Sequence(0, x509_name(&x.subject)));
    } else {
        println!("Failed: no subject name");
        return None;
    }

    /* Subject Public Key Info */
    match build_pub_key(&x.pub_key) {
        Some(v) => body.push(ASN1Block::Sequence(0, v)),
        None => return None,
    }

    /* Extensions */
    let mut ext = Vec::new();
    for i in 0..x.ext.len() {
        ext.push(ASN1Block::Sequence(
            0,
            x509_ext(&x.ext[x.ext.len() - i - 1]),
        ));
    }

    if x.ext.len() > 0 {
        body.push(extension_explicit(ext));
    }

    Some(body)
}

impl X509 {
    pub fn builder() -> X509Builder {
        X509Builder::default()
    }

    pub fn sign<F>(self, sign_cb: F, sign_key: &Vec<u8>) -> Option<X509>
    where
        F: Fn(&Vec<u8>, &Vec<u8>) -> Option<Vec<u8>>,
    {
        let body = x509_body(&self)?;
        let data = match serialize(&ASN1Block::Sequence(0, body)) {
            Some(d) => d,
            None => {
                println!("Failed: serialize()");
                return None;
            }
        };

        let sign = match sign_cb(&data, sign_key) {
            Some(s) => s,
            None => {
                println!("Failed: signature");
                return None;
            }
        };

        let x = X509 {
            version: self.version,
            sn: self.sn,
            issuer: self.issuer,
            subject: self.subject,
            not_before: self.not_before,
            not_after: self.not_after,
            pub_key: self.pub_key,
            ext: self.ext,
            sign_oid: self.sign_oid,
            sign: sign,
        };

        Some(x)
    }

    pub fn verify<F>(&self, verify_cb: F, pub_key: &Vec<u8>) -> Option<bool>
    where
        F: Fn(&Vec<u8>, &Vec<u8>, &Vec<u8>) -> Option<bool>,
    {
        let body = x509_body(&self)?;
        let data = match serialize(&ASN1Block::Sequence(0, body)) {
            Some(d) => d,
            None => {
                println!("Failed: serialize()");
                return None;
            }
        };

        if self.sign.len() == 0 {
            println!("Failed: no signature");
            return None;
        }

        verify_cb(pub_key, &data, &self.sign)
    }

    pub fn x509_enc(self) -> Option<Vec<u8>> {
        let mut x509 = Vec::new();
        let body = x509_body(&self)?;

        x509.push(ASN1Block::Sequence(0, body));
        match self.pub_key {
            Some(PubKey::Rsa(_)) => x509.push(ASN1Block::Sequence(0, null_oid(&self.sign_oid))),
            Some(PubKey::Ec(_)) => x509.push(ASN1Block::Sequence(0, vec_oid(&self.sign_oid))),
            None => return None,
        }

        if self.sign.len() == 0 {
            println!("Failed: no signature");
            return None;
        }

        x509.push(ASN1Block::BitString(0, self.sign.len() * 8, self.sign));

        let mut x509_full = Vec::new();
        x509_full.push(ASN1Block::Sequence(0, x509));

        serialize(x509_full.first()?)
    }

    pub fn pub_key(&self) -> Option<Vec<u8>> {
        let asn = match build_pub_key(&self.pub_key) {
            Some(a) => a,
            None => return None,
        };

        match simple_asn1::to_der(&ASN1Block::Sequence(0, asn)) {
            Ok(der) => Some(der),
            Err(_) => {
                println!("Failed to serialize Public Key");
                return None;
            }
        }
    }
}

#[derive(Default)]
pub struct X509Builder {
    version: Option<u64>,
    sn: Vec<u8>,
    issuer: Vec<X509Name>,
    subject: Vec<X509Name>,
    not_before: Option<X509Time>,
    not_after: Option<X509Time>,
    pub_key: Option<PubKey>,
    ext: Vec<X509Ext>,
    sign_oid: Vec<u64>,
}

impl X509Builder {
    pub fn new(sn: Vec<u8>) -> X509Builder {
        X509Builder {
            version: None,
            sn: sn,
            issuer: Vec::new(),
            subject: Vec::new(),
            not_before: None,
            not_after: None,
            pub_key: None,
            ext: Vec::new(),
            sign_oid: Vec::new(),
        }
    }

    pub fn version(mut self, version: u64) -> X509Builder {
        self.version = Some(version);
        self
    }

    pub fn issuer_utf8(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Utf8(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn issuer_prstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::PrStr(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn issuer_ttxstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::TtxStr(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn issuer_ia5str(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Ia5Str(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn subject_utf8(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Utf8(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn subject_prstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::PrStr(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn subject_ttxstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::TtxStr(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn subject_ia5str(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Ia5Str(OidStr {
            oid: oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn not_before_utc(mut self, not_before: i64) -> X509Builder {
        self.not_before = Some(X509Time::Utc(not_before));
        self
    }

    pub fn not_before_gen(mut self, not_before: i64) -> X509Builder {
        self.not_before = Some(X509Time::Gen(not_before));
        self
    }

    pub fn not_after_utc(mut self, not_after: i64) -> X509Builder {
        self.not_after = Some(X509Time::Utc(not_after));
        self
    }

    pub fn not_after_gen(mut self, not_after: i64) -> X509Builder {
        self.not_after = Some(X509Time::Gen(not_after));
        self
    }

    pub fn pub_key_rsa(mut self, oid: Vec<u64>, n: Vec<u8>, e: u32) -> X509Builder {
        let key = PubKey::Rsa(RsaPub {
            pub_oid: oid,
            n: n,
            e: e,
        });
        self.pub_key = Some(key);
        self
    }

    pub fn pub_key_ec(mut self, oid: Vec<u64>, key: Vec<u8>, curve: Vec<u64>) -> X509Builder {
        let key = PubKey::Ec(EcPub {
            pub_oid: oid,
            key: key,
            curve: curve,
        });
        self.pub_key = Some(key);
        self
    }

    pub fn pub_key_der(mut self, der: &Vec<u8>) -> X509Builder {
        self.pub_key = get_pub_der(der);
        self
    }

    pub fn ext(mut self, ext: X509Ext) -> X509Builder {
        self.ext.push(ext);
        self
    }

    pub fn ext_raw(mut self, oid: Vec<u64>, critical: bool, data: Vec<u8>) -> X509Builder {
        let ext = X509Ext {
            oid: oid,
            critical: critical,
            data: data,
        };
        self.ext.push(ext);
        self
    }

    pub fn sign_oid(mut self, oid: Vec<u64>) -> X509Builder {
        self.sign_oid = oid;
        self
    }

    pub fn build(self) -> X509 {
        X509 {
            version: self.version,
            sn: self.sn,
            issuer: self.issuer,
            subject: self.subject,
            not_before: self.not_before,
            not_after: self.not_after,
            pub_key: self.pub_key,
            ext: self.ext,
            sign_oid: self.sign_oid,
            sign: Vec::new(),
        }
    }
}

fn get_asn1_seq(v: &Vec<ASN1Block>, idx: usize) -> Option<&Vec<ASN1Block>> {
    let block = v.get(idx)?;
    match block {
        ASN1Block::Sequence(_, vec) => Some(vec),
        _ => None,
    }
}

fn get_asn1_set(v: &Vec<ASN1Block>, idx: usize) -> Option<&Vec<ASN1Block>> {
    let block = v.get(idx)?;
    match block {
        ASN1Block::Set(_, vec) => Some(vec),
        _ => None,
    }
}

fn get_serial_number(v: &Vec<ASN1Block>, idx: usize) -> Option<Vec<u8>> {
    let block = v.get(idx)?;
    match block {
        ASN1Block::Integer(_, b) => Some(BigInt::to_signed_bytes_be(b)),
        _ => None,
    }
}

fn get_version(v: &Vec<ASN1Block>) -> Option<u64> {
    let block = v.get(0)?;
    match block {
        ASN1Block::Explicit(_, _, tag, val) => {
            if tag.to_u64() == Some(0) {
                match Deref::deref(val) {
                    ASN1Block::Integer(_, b) => b.to_u64(),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_sign_oid(v: &Vec<ASN1Block>, idx: usize) -> Option<Vec<u64>> {
    let vec = get_asn1_seq(v, idx)?;
    match vec.get(0)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().ok(),
        _ => return None,
    }
}

fn get_x509_name(v: &Vec<ASN1Block>, idx: usize) -> Option<Vec<X509Name>> {
    let vec = get_asn1_seq(v, idx)?;
    let mut ret = Vec::new();

    for i in 0..vec.len() {
        let set = get_asn1_set(vec, i)?;
        let seq = get_asn1_seq(set, 0)?;
        let oid = match seq.get(0)? {
            ASN1Block::ObjectIdentifier(_, o) => o.as_vec().ok()?,
            _ => return None,
        };

        let name = match seq.get(1)? {
            ASN1Block::UTF8String(_, d) => X509Name::Utf8(OidStr {
                oid: oid,
                data: d.to_string(),
            }),
            ASN1Block::PrintableString(_, d) => X509Name::PrStr(OidStr {
                oid: oid,
                data: d.to_string(),
            }),
            ASN1Block::TeletexString(_, d) => X509Name::TtxStr(OidStr {
                oid: oid,
                data: d.to_string(),
            }),
            ASN1Block::IA5String(_, d) => X509Name::Ia5Str(OidStr {
                oid: oid,
                data: d.to_string(),
            }),
            _ => return None,
        };

        ret.push(name);
    }

    Some(ret)
}

fn get_rsa_pub_key(v: &Vec<ASN1Block>, idx: usize) -> Option<PubKey> {
    let vec = get_asn1_seq(v, idx)?;
    let seq = get_asn1_seq(vec, 0)?;
    let pub_oid = match seq.get(0)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().ok()?,
        _ => return None,
    };

    let der = match vec.get(1)? {
        ASN1Block::BitString(_, _, d) => d,
        _ => return None,
    };

    let sk = simple_asn1::from_der(der).ok()?;
    let key = get_asn1_seq(&sk, 0)?;
    let n = match key.get(0)? {
        ASN1Block::Integer(_, bi) => BigInt::to_signed_bytes_be(bi),
        _ => return None,
    };
    let e = match key.get(1)? {
        ASN1Block::Integer(_, bi) => <u32>::try_from(bi).ok()?,
        _ => return None,
    };

    let pub_key = PubKey::Rsa(RsaPub {
        pub_oid: pub_oid,
        n: n,
        e: e,
    });

    Some(pub_key)
}

fn get_ec_pub_key(v: &Vec<ASN1Block>, idx: usize) -> Option<PubKey> {
    let vec = get_asn1_seq(v, idx)?;
    let seq = get_asn1_seq(vec, 0)?;
    let pub_oid = match seq.get(0)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().ok()?,
        _ => return None,
    };

    let curve = match seq.get(1)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().ok()?,
        _ => return None,
    };

    let key = match vec.get(1)? {
        ASN1Block::BitString(_, _, k) => k,
        _ => return None,
    };

    let pub_key = PubKey::Ec(EcPub {
        pub_oid: pub_oid,
        key: key.to_vec(),
        curve: curve,
    });

    Some(pub_key)
}

fn get_pub_key(v: &Vec<ASN1Block>, idx: usize) -> Option<PubKey> {
    let mut pub_key = get_rsa_pub_key(v, idx);
    if pub_key == None {
        pub_key = get_ec_pub_key(v, idx);
    }

    pub_key
}

fn get_pub_der(der: &Vec<u8>) -> Option<PubKey> {
    let asn = match simple_asn1::from_der(der) {
        Ok(a) => a,
        Err(_) => {
            println!("Failed to deserialize Public Key");
            return None;
        }
    };

    get_pub_key(&asn, 0)
}

fn get_x509_time(v: &Vec<ASN1Block>, idx: usize) -> Option<(X509Time, X509Time)> {
    let vec = get_asn1_seq(v, idx)?;

    let not_before = match vec.get(0)? {
        ASN1Block::UTCTime(_, t) => X509Time::Utc(DateTime::<Utc>::timestamp(t)),
        ASN1Block::GeneralizedTime(_, t) => X509Time::Gen(DateTime::<Utc>::timestamp(t)),
        _ => return None,
    };

    let not_after = match vec.get(1)? {
        ASN1Block::UTCTime(_, t) => X509Time::Utc(DateTime::<Utc>::timestamp(t)),
        ASN1Block::GeneralizedTime(_, t) => X509Time::Gen(DateTime::<Utc>::timestamp(t)),
        _ => return None,
    };

    Some((not_before, not_after))
}

fn get_ext_raw(v: &Vec<ASN1Block>) -> Option<Vec<X509Ext>> {
    let mut ret = Vec::new();

    for i in (0..v.len()).rev() {
        let seq = get_asn1_seq(v, i)?;
        let oid = match seq.get(0)? {
            ASN1Block::ObjectIdentifier(_, o) => o.as_vec().ok()?,
            _ => return None,
        };

        let critical = match seq.get(1)? {
            ASN1Block::Boolean(_, c) => *c,
            _ => false,
        };

        let idx = match critical {
            false => 1,
            true => 2,
        };

        let data = match seq.get(idx)? {
            ASN1Block::OctetString(_, d) => d,
            _ => return None,
        };

        ret.push(X509Ext {
            oid: oid,
            critical: critical,
            data: data.to_vec(),
        });
    }

    Some(ret)
}

fn get_extensions(v: &Vec<ASN1Block>, idx: usize) -> Option<Vec<X509Ext>> {
    let block = match v.get(idx) {
        Some(b) => b,
        _ => return Some(Vec::new()),
    };

    match block {
        ASN1Block::Explicit(_, _, tag, val) => {
            if tag.to_u64() == Some(3) {
                match Deref::deref(val) {
                    ASN1Block::Sequence(_, e) => get_ext_raw(e),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_signature(v: &Vec<ASN1Block>) -> Option<Vec<u8>> {
    match v.get(2)? {
        ASN1Block::BitString(_, _, s) => Some(s.to_vec()),
        _ => None,
    }
}

pub trait X509Deserialize {
    fn x509_dec(&self) -> Option<X509>;
}

impl X509Deserialize for Vec<u8> {
    fn x509_dec(&self) -> Option<X509> {
        let x509_full = match simple_asn1::from_der(self) {
            Ok(a) => a,
            Err(_) => {
                println!("Failed: simple_asn1::from_der()");
                return None;
            }
        };

        let x509 = match get_asn1_seq(&x509_full, 0) {
            Some(a) => a,
            None => {
                println!("Failed to get x509");
                return None;
            }
        };

        let body = match get_asn1_seq(&x509, 0) {
            Some(a) => a,
            None => {
                println!("Failed to get body");
                return None;
            }
        };

        /* Version */
        let version = get_version(body);
        let mut idx = match version {
            Some(_) => 1,
            None => 0,
        };

        /* Serial Number */
        let sn = match get_serial_number(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get SerialNumber");
                return None;
            }
        };
        idx += 1;

        /* Signature Algorithm */
        let sign_oid = match get_sign_oid(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get Signature Algorithm OID");
                return None;
            }
        };
        idx += 1;

        /* Issuer */
        let issuer = match get_x509_name(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get Issuer");
                return None;
            }
        };
        idx += 1;

        /* Validity time */
        let (not_before, not_after) = match get_x509_time(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get Validity time");
                return None;
            }
        };
        idx += 1;

        /* Subject */
        let subject = match get_x509_name(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get Subject");
                return None;
            }
        };
        idx += 1;

        /* Subject Public Key Info */
        let pub_key = match get_pub_key(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get Subject Public Key");
                return None;
            }
        };
        idx += 1;

        /* Extensions */
        let ext = match get_extensions(body, idx) {
            Some(a) => a,
            None => {
                println!("Failed to get Extensions");
                return None;
            }
        };

        /* Signature */
        let sign = match get_signature(&x509) {
            Some(a) => a,
            None => {
                println!("Failed to get Signature");
                return None;
            }
        };

        let x = X509 {
            version: version,
            sn: sn,
            issuer: issuer,
            subject: subject,
            not_before: Some(not_before),
            not_after: Some(not_after),
            pub_key: Some(pub_key),
            ext: ext,
            sign_oid: sign_oid,
            sign: sign,
        };

        Some(x)
    }
}
