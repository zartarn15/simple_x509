use crate::{Error, X509Ext};
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
    Any(Vec<ASN1Block>),
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

fn serialize(a: &ASN1Block) -> Result<Vec<u8>, Error> {
    simple_asn1::to_der(a).map_err(Error::Serialize)
}

fn oid_new(id: &[u64]) -> OID {
    let mut res = Vec::new();

    for it in id {
        res.push(BigUint::from(*it));
    }

    OID::new(res)
}

fn seq_oid_str(v: &OidStr) -> Vec<ASN1Block> {
    let vec = vec![
        ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)),
        ASN1Block::PrintableString(1, String::from(&v.data)),
    ];

    vec![ASN1Block::Sequence(0, vec)]
}

fn seq_oid_utf8(v: &OidStr) -> Vec<ASN1Block> {
    let vec = vec![
        ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)),
        ASN1Block::UTF8String(1, String::from(&v.data)),
    ];

    vec![ASN1Block::Sequence(0, vec)]
}

fn seq_oid_ttx(v: &OidStr) -> Vec<ASN1Block> {
    let vec = vec![
        ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)),
        ASN1Block::TeletexString(1, String::from(&v.data)),
    ];

    vec![ASN1Block::Sequence(0, vec)]
}

fn seq_oid_ia5(v: &OidStr) -> Vec<ASN1Block> {
    let vec = vec![
        ASN1Block::ObjectIdentifier(0, oid_new(&v.oid)),
        ASN1Block::IA5String(1, String::from(&v.data)),
    ];

    vec![ASN1Block::Sequence(0, vec)]
}

fn x509_name(name: &[X509Name]) -> Vec<ASN1Block> {
    let mut n = Vec::new();

    for it in name {
        match it {
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
        X509Time::Utc(nb) => v.push(ASN1Block::UTCTime(0, Utc.timestamp_opt(*nb, 0).unwrap())),
        X509Time::Gen(nb) => v.push(ASN1Block::GeneralizedTime(
            0,
            Utc.timestamp_opt(*nb, 0).unwrap(),
        )),
    }

    match not_after {
        X509Time::Utc(na) => v.push(ASN1Block::UTCTime(0, Utc.timestamp_opt(*na, 0).unwrap())),
        X509Time::Gen(na) => v.push(ASN1Block::GeneralizedTime(
            0,
            Utc.timestamp_opt(*na, 0).unwrap(),
        )),
    }

    v
}

fn version_explicit(val: u64) -> ASN1Block {
    ASN1Block::Explicit(
        ASN1Class::ContextSpecific,
        0,
        BigUint::from(0_u32),
        Box::new(ASN1Block::Integer(0, BigInt::from(val))),
    )
}

fn extension_explicit(ext: Vec<ASN1Block>) -> ASN1Block {
    ASN1Block::Explicit(
        ASN1Class::ContextSpecific,
        0,
        BigUint::from(3_u32),
        Box::new(ASN1Block::Sequence(0, ext)),
    )
}

fn x509_ext(e: &X509Ext) -> Vec<ASN1Block> {
    let mut ext = vec![ASN1Block::ObjectIdentifier(0, oid_new(&e.oid))];
    if e.critical {
        ext.push(ASN1Block::Boolean(0, true));
    }
    ext.push(ASN1Block::OctetString(0, e.data.clone()));

    ext
}

fn null_oid(oid: &[u64]) -> Vec<ASN1Block> {
    vec![
        ASN1Block::ObjectIdentifier(0, oid_new(oid)),
        ASN1Block::Null(0),
    ]
}

fn vec_oid(oid: &[u64]) -> Vec<ASN1Block> {
    vec![ASN1Block::ObjectIdentifier(0, oid_new(oid))]
}

fn rsa_pub(rsa: &RsaPub) -> Result<Vec<ASN1Block>, Error> {
    let r = vec![
        ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&rsa.n)),
        ASN1Block::Integer(0, BigInt::from(rsa.e)),
    ];

    let der = simple_asn1::to_der(&ASN1Block::Sequence(0, r)).map_err(Error::RsaPub)?;

    Ok(vec![
        ASN1Block::Sequence(0, null_oid(&rsa.pub_oid)),
        ASN1Block::BitString(0, der.len() * 8, der),
    ])
}

fn ec_pub(ec: &EcPub) -> Result<Vec<ASN1Block>, Error> {
    let e = vec![
        ASN1Block::ObjectIdentifier(0, oid_new(&ec.pub_oid)),
        ASN1Block::ObjectIdentifier(0, oid_new(&ec.curve)),
    ];

    Ok(vec![
        ASN1Block::Sequence(0, e),
        ASN1Block::BitString(0, ec.key.len() * 8, ec.key.clone()),
    ])
}

fn build_pub_key(pub_key: &Option<PubKey>) -> Result<Vec<ASN1Block>, Error> {
    match pub_key {
        Some(PubKey::Rsa(ref rsa)) => rsa_pub(rsa),
        Some(PubKey::Ec(ref ec)) => ec_pub(ec),
        Some(PubKey::Any(ref key)) => Ok(key.to_vec()),
        None => Err(Error::NoPubKey),
    }
}

fn x509_body(x: &X509) -> Result<Vec<ASN1Block>, Error> {
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
        Some(PubKey::Any(_)) => body.push(ASN1Block::Sequence(0, vec_oid(&x.sign_oid))),
        None => return Err(Error::NoPubKeyBody),
    }

    /* Issuer name */
    if !x.issuer.is_empty() {
        body.push(ASN1Block::Sequence(0, x509_name(&x.issuer)));
    } else {
        return Err(Error::NoIssuerName);
    }

    /* Validity time */
    if x.not_before == None || x.not_after == None {
        return Err(Error::NoValidityTime);
    }

    let validity = validity_time(
        x.not_before.as_ref().unwrap(),
        x.not_after.as_ref().unwrap(),
    );
    body.push(ASN1Block::Sequence(0, validity));

    /* Subject name */
    if !x.subject.is_empty() {
        body.push(ASN1Block::Sequence(0, x509_name(&x.subject)));
    } else {
        return Err(Error::NoSubjectName);
    }

    /* Subject Public Key Info */
    let pk = build_pub_key(&x.pub_key)?;
    body.push(ASN1Block::Sequence(0, pk));

    /* Extensions */
    let mut ext = Vec::new();
    for i in 0..x.ext.len() {
        ext.push(ASN1Block::Sequence(
            0,
            x509_ext(&x.ext[x.ext.len() - i - 1]),
        ));
    }

    if !x.ext.is_empty() {
        body.push(extension_explicit(ext));
    }

    Ok(body)
}

impl X509 {
    pub fn builder() -> X509Builder {
        X509Builder::default()
    }

    pub fn sign<F>(self, sign_cb: F, sign_key: &[u8]) -> Result<X509, Error>
    where
        F: Fn(&[u8], &[u8]) -> Option<Vec<u8>>,
    {
        let body = x509_body(&self)?;
        let data = serialize(&ASN1Block::Sequence(0, body))?;

        let sign = match sign_cb(&data, sign_key) {
            Some(s) => s,
            None => return Err(Error::Signature),
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
            sign,
        };

        Ok(x)
    }

    pub fn verify<F>(&self, verify_cb: F, pub_key: &[u8]) -> Result<bool, Error>
    where
        F: Fn(&[u8], &[u8], &[u8]) -> Option<bool>,
    {
        let body = x509_body(self)?;
        let data = serialize(&ASN1Block::Sequence(0, body))?;

        if self.sign.is_empty() {
            return Err(Error::NoSignature);
        }

        let res = verify_cb(pub_key, &data, &self.sign).ok_or(Error::Verify)?;

        Ok(res)
    }

    pub fn x509_enc(self) -> Result<Vec<u8>, Error> {
        let mut x509 = Vec::new();
        let body = x509_body(&self)?;

        x509.push(ASN1Block::Sequence(0, body));
        match self.pub_key {
            Some(PubKey::Rsa(_)) => x509.push(ASN1Block::Sequence(0, null_oid(&self.sign_oid))),
            Some(PubKey::Ec(_)) => x509.push(ASN1Block::Sequence(0, vec_oid(&self.sign_oid))),
            Some(PubKey::Any(_)) => x509.push(ASN1Block::Sequence(0, vec_oid(&self.sign_oid))),
            None => return Err(Error::NoPubKeyEnc),
        }

        if self.sign.is_empty() {
            return Err(Error::NoSignatureEnc);
        }

        x509.push(ASN1Block::BitString(0, self.sign.len() * 8, self.sign));

        let x509_full = vec![ASN1Block::Sequence(0, x509)];

        serialize(x509_full.first().ok_or(Error::EncFirst)?)
    }

    pub fn pub_key(&self) -> Result<Vec<u8>, Error> {
        let asn = build_pub_key(&self.pub_key)?;

        simple_asn1::to_der(&ASN1Block::Sequence(0, asn)).map_err(Error::PubKeyEnc)
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
            sn,
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
            oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn issuer_prstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::PrStr(OidStr {
            oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn issuer_ttxstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::TtxStr(OidStr {
            oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn issuer_ia5str(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Ia5Str(OidStr {
            oid,
            data: data.to_string(),
        });
        self.issuer.push(name);
        self
    }

    pub fn subject_utf8(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Utf8(OidStr {
            oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn subject_prstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::PrStr(OidStr {
            oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn subject_ttxstr(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::TtxStr(OidStr {
            oid,
            data: data.to_string(),
        });
        self.subject.push(name);
        self
    }

    pub fn subject_ia5str(mut self, oid: Vec<u64>, data: &str) -> X509Builder {
        let name = X509Name::Ia5Str(OidStr {
            oid,
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

    pub fn pub_key_rsa(mut self, pub_oid: Vec<u64>, n: Vec<u8>, e: u32) -> X509Builder {
        let key = PubKey::Rsa(RsaPub { pub_oid, n, e });
        self.pub_key = Some(key);
        self
    }

    pub fn pub_key_ec(mut self, pub_oid: Vec<u64>, key: Vec<u8>, curve: Vec<u64>) -> X509Builder {
        let key = PubKey::Ec(EcPub {
            pub_oid,
            key,
            curve,
        });
        self.pub_key = Some(key);
        self
    }

    pub fn pub_key_der(mut self, der: &[u8]) -> X509Builder {
        self.pub_key = get_pub_der(der).ok();
        self
    }

    pub fn ext(mut self, ext: X509Ext) -> X509Builder {
        self.ext.push(ext);
        self
    }

    pub fn ext_raw(mut self, oid: Vec<u64>, critical: bool, data: Vec<u8>) -> X509Builder {
        let ext = X509Ext {
            oid,
            critical,
            data,
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

fn get_asn1_seq(v: &[ASN1Block], idx: usize) -> Result<&Vec<ASN1Block>, Error> {
    let block = v.get(idx).ok_or(Error::SeqNoIdx(idx))?;
    match block {
        ASN1Block::Sequence(_, vec) => Ok(vec),
        _ => Err(Error::Seq(idx)),
    }
}

fn get_asn1_set(v: &[ASN1Block], idx: usize) -> Result<&Vec<ASN1Block>, Error> {
    let block = v.get(idx).ok_or(Error::SetNoIdx(idx))?;
    match block {
        ASN1Block::Set(_, vec) => Ok(vec),
        _ => Err(Error::Set(idx)),
    }
}

fn get_serial_number(v: &[ASN1Block], idx: usize) -> Result<Vec<u8>, Error> {
    let block = v.get(idx).ok_or(Error::NumNoIdx(idx))?;
    match block {
        ASN1Block::Integer(_, b) => Ok(BigInt::to_signed_bytes_be(b)),
        _ => Err(Error::Num(idx)),
    }
}

fn get_version(v: &[ASN1Block]) -> Result<u64, Error> {
    let block = v.get(0).ok_or(Error::VersionIdx)?;
    match block {
        ASN1Block::Explicit(_, _, tag, val) => {
            if tag.to_u64() == Some(0) {
                match Deref::deref(val) {
                    ASN1Block::Integer(_, b) => b.to_u64().ok_or(Error::VecToU64),
                    _ => Err(Error::VerDeref),
                }
            } else {
                Err(Error::VerTag(tag.to_u64()))
            }
        }
        _ => Err(Error::VerBlock),
    }
}

fn get_sign_oid(v: &[ASN1Block], idx: usize) -> Result<Vec<u64>, Error> {
    let vec = get_asn1_seq(v, idx)?;
    match vec.get(0).ok_or(Error::OidNoIdx(idx))? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().map_err(Error::SignOidDec),
        _ => Err(Error::Oid(idx)),
    }
}

fn get_x509_name(v: &[ASN1Block], idx: usize) -> Result<Vec<X509Name>, Error> {
    let vec = get_asn1_seq(v, idx)?;
    let mut ret = Vec::new();

    for i in 0..vec.len() {
        let set = get_asn1_set(vec, i)?;
        let seq = get_asn1_seq(set, 0)?;
        let oid = match seq.get(0).ok_or(Error::NameGet)? {
            ASN1Block::ObjectIdentifier(_, o) => o.as_vec().map_err(Error::NameOid)?,
            _ => return Err(Error::NameObjOid),
        };

        let name = match seq.get(1).ok_or(Error::NameGet1)? {
            ASN1Block::UTF8String(_, d) => X509Name::Utf8(OidStr {
                oid,
                data: d.to_string(),
            }),
            ASN1Block::PrintableString(_, d) => X509Name::PrStr(OidStr {
                oid,
                data: d.to_string(),
            }),
            ASN1Block::TeletexString(_, d) => X509Name::TtxStr(OidStr {
                oid,
                data: d.to_string(),
            }),
            ASN1Block::IA5String(_, d) => X509Name::Ia5Str(OidStr {
                oid,
                data: d.to_string(),
            }),
            _ => return Err(Error::NoName),
        };

        ret.push(name);
    }

    Ok(ret)
}

fn get_rsa_pub_key(v: &[ASN1Block], idx: usize) -> Result<PubKey, Error> {
    let vec = get_asn1_seq(v, idx)?;
    let seq = get_asn1_seq(vec, 0)?;
    let pub_oid = match seq.get(0).ok_or(Error::RsaPubGet0)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().map_err(Error::RsaPubDec)?,
        _ => return Err(Error::RsaPubOid),
    };

    let der = match vec.get(1).ok_or(Error::RsaPubGet1)? {
        ASN1Block::BitString(_, _, d) => d,
        _ => return Err(Error::RsaPubDer),
    };

    let sk = simple_asn1::from_der(der).map_err(Error::RsaPubDecSk)?;
    let key = get_asn1_seq(&sk, 0)?;
    let n = match key.get(0).ok_or(Error::RsaPubGet2)? {
        ASN1Block::Integer(_, bi) => BigInt::to_signed_bytes_be(bi),
        _ => return Err(Error::RsaPubN),
    };
    let e = match key.get(1).ok_or(Error::RsaPubGet3)? {
        ASN1Block::Integer(_, bi) => <u32>::try_from(bi).map_err(|_| Error::RsaPubFrom)?,
        _ => return Err(Error::RsaPubE),
    };

    Ok(PubKey::Rsa(RsaPub { pub_oid, n, e }))
}

fn get_ec_pub_key(v: &[ASN1Block], idx: usize) -> Result<PubKey, Error> {
    let vec = get_asn1_seq(v, idx)?;
    let seq = get_asn1_seq(vec, 0)?;
    let pub_oid = match seq.get(0).ok_or(Error::EcPubGet0)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().map_err(Error::EcPubDec)?,
        _ => return Err(Error::EcPubOId),
    };

    let curve = match seq.get(1).ok_or(Error::EcPubGet1)? {
        ASN1Block::ObjectIdentifier(_, o) => o.as_vec().map_err(Error::EcPubDecCur)?,
        _ => return Err(Error::EcPubCurve),
    };

    let key = match vec.get(1).ok_or(Error::EcPubGet2)? {
        ASN1Block::BitString(_, _, k) => k,
        _ => return Err(Error::EcPubKey),
    };

    Ok(PubKey::Ec(EcPub {
        pub_oid,
        key: key.to_vec(),
        curve,
    }))
}

fn get_any_pub_key(v: &[ASN1Block], idx: usize) -> Result<PubKey, Error> {
    let vec = get_asn1_seq(v, idx)?;

    Ok(PubKey::Any(vec.to_vec()))
}

fn get_pub_key(v: &[ASN1Block], idx: usize) -> Result<PubKey, Error> {
    // TODO: get algorithm from OID
    Ok(get_rsa_pub_key(v, idx)
        .unwrap_or(get_ec_pub_key(v, idx).unwrap_or(get_any_pub_key(v, idx)?)))
}

fn get_pub_der(der: &[u8]) -> Result<PubKey, Error> {
    let asn = simple_asn1::from_der(der).map_err(Error::PubDec)?;

    get_pub_key(&asn, 0)
}

fn get_x509_time(v: &[ASN1Block], idx: usize) -> Result<(X509Time, X509Time), Error> {
    let vec = get_asn1_seq(v, idx)?;

    let not_before = match vec.get(0).ok_or(Error::TimeIdx0)? {
        ASN1Block::UTCTime(_, t) => X509Time::Utc(DateTime::<Utc>::timestamp(t)),
        ASN1Block::GeneralizedTime(_, t) => X509Time::Gen(DateTime::<Utc>::timestamp(t)),
        _ => return Err(Error::TimeNb),
    };

    let not_after = match vec.get(1).ok_or(Error::TimeIdx1)? {
        ASN1Block::UTCTime(_, t) => X509Time::Utc(DateTime::<Utc>::timestamp(t)),
        ASN1Block::GeneralizedTime(_, t) => X509Time::Gen(DateTime::<Utc>::timestamp(t)),
        _ => return Err(Error::TimeNa),
    };

    Ok((not_before, not_after))
}

fn get_ext_raw(v: &[ASN1Block]) -> Result<Vec<X509Ext>, Error> {
    let mut ret = Vec::new();

    for i in (0..v.len()).rev() {
        let seq = get_asn1_seq(v, i)?;
        let oid = match seq.get(0).ok_or(Error::ExtRawIdx0)? {
            ASN1Block::ObjectIdentifier(_, o) => o.as_vec().map_err(Error::ExtRawOidId)?,
            _ => return Err(Error::ExtRawOid),
        };

        let critical = match seq.get(1).ok_or(Error::ExtRawIdx1)? {
            ASN1Block::Boolean(_, c) => *c,
            _ => false,
        };

        let idx = match critical {
            false => 1,
            true => 2,
        };

        let data = match seq.get(idx).ok_or(Error::ExtRawIdx2)? {
            ASN1Block::OctetString(_, d) => d,
            _ => return Err(Error::ExtRawData),
        };

        ret.push(X509Ext {
            oid,
            critical,
            data: data.to_vec(),
        });
    }

    Ok(ret)
}

fn get_extensions(v: &[ASN1Block], idx: usize) -> Result<Vec<X509Ext>, Error> {
    let block = match v.get(idx) {
        Some(b) => b,
        _ => return Ok(Vec::new()),
    };

    match block {
        ASN1Block::Explicit(_, _, tag, val) => {
            if tag.to_u64() == Some(3) {
                match Deref::deref(val) {
                    ASN1Block::Sequence(_, e) => get_ext_raw(e),
                    _ => Err(Error::ExtDeref),
                }
            } else {
                Err(Error::ExtTag)
            }
        }
        _ => Err(Error::ExtExpl),
    }
}

fn get_signature(v: &[ASN1Block]) -> Result<Vec<u8>, Error> {
    match v.get(2).ok_or(Error::GetSignIdx)? {
        ASN1Block::BitString(_, _, s) => Ok(s.to_vec()),
        _ => Err(Error::GetSign),
    }
}

pub trait X509Deserialize {
    fn x509_dec(&self) -> Result<X509, Error>;
}

impl X509Deserialize for Vec<u8> {
    fn x509_dec(&self) -> Result<X509, Error> {
        x509_decode(self)
    }
}

impl X509Deserialize for &[u8] {
    fn x509_dec(&self) -> Result<X509, Error> {
        x509_decode(self)
    }
}

fn x509_decode(der: &[u8]) -> Result<X509, Error> {
    let x509_full = simple_asn1::from_der(der).map_err(Error::DecFull)?;
    let x509 = get_asn1_seq(&x509_full, 0)?;
    let body = get_asn1_seq(x509, 0)?;

    /* Version */
    let version = get_version(body).ok();
    let mut idx = match version {
        Some(_) => 1,
        None => 0,
    };

    /* Serial Number */
    let sn = get_serial_number(body, idx)?;
    idx += 1;

    /* Signature Algorithm */
    let sign_oid = get_sign_oid(body, idx)?;
    idx += 1;

    /* Issuer */
    let issuer = get_x509_name(body, idx)?;
    idx += 1;

    /* Validity time */
    let (not_before, not_after) = get_x509_time(body, idx)?;
    idx += 1;

    /* Subject */
    let subject = get_x509_name(body, idx)?;
    idx += 1;

    /* Subject Public Key Info */
    let pub_key = get_pub_key(body, idx)?;
    idx += 1;

    /* Extensions */
    let ext = get_extensions(body, idx)?;

    /* Signature */
    let sign = get_signature(x509)?;

    Ok(X509 {
        version,
        sn,
        issuer,
        subject,
        not_before: Some(not_before),
        not_after: Some(not_after),
        pub_key: Some(pub_key),
        ext,
        sign_oid,
        sign,
    })
}
