use crate::Error;
use simple_asn1::ASN1Block;

#[derive(Debug, PartialEq)]
pub enum X509KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CRLSign,
    EncipherOnly,
    DecipherOnly,
}

#[derive(Debug, PartialEq)]
pub struct X509Ext {
    pub oid: Vec<u64>,
    pub critical: bool,
    pub data: Vec<u8>,
}

fn build_key_usage(bits: Vec<X509KeyUsage>) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0];
    let mut n: usize = 0;

    for it in &bits {
        match it {
            X509KeyUsage::DigitalSignature => {
                b[0] |= 1 << 7;
                n = std::cmp::max(n, 1);
            }
            X509KeyUsage::NonRepudiation => {
                b[0] |= 1 << 6;
                n = std::cmp::max(n, 2);
            }
            X509KeyUsage::KeyEncipherment => {
                b[0] |= 1 << 5;
                n = std::cmp::max(n, 3);
            }
            X509KeyUsage::DataEncipherment => {
                b[0] |= 1 << 4;
                n = std::cmp::max(n, 4);
            }
            X509KeyUsage::KeyAgreement => {
                b[0] |= 1 << 3;
                n = std::cmp::max(n, 5);
            }
            X509KeyUsage::KeyCertSign => {
                b[0] |= 1 << 2;
                n = std::cmp::max(n, 6);
            }
            X509KeyUsage::CRLSign => {
                b[0] |= 1 << 1;
                n = std::cmp::max(n, 7);
            }
            X509KeyUsage::EncipherOnly => {
                b[0] |= 1 << 0;
                n = std::cmp::max(n, 8);
            }
            X509KeyUsage::DecipherOnly => {
                if b.len() < 2 {
                    b.push(0);
                }
                b[1] |= 1 << 7;
                n = std::cmp::max(n, 9);
            }
        };
    }

    simple_asn1::to_der(&ASN1Block::BitString(0, n, b)).unwrap()
}

impl X509Ext {
    pub fn builder() -> X509ExtBuilder {
        X509ExtBuilder::default()
    }
}

#[derive(Default)]
pub struct X509ExtBuilder {
    oid: Vec<u64>,
    critical: bool,
    data: Vec<u8>,
}

impl X509ExtBuilder {
    pub fn new() -> X509ExtBuilder {
        X509ExtBuilder {
            oid: Vec::new(),
            critical: false,
            data: Vec::new(),
        }
    }

    pub fn key_usage(mut self, bits: Vec<X509KeyUsage>) -> X509ExtBuilder {
        self.oid = vec![2, 5, 29, 15]; /* keyUsage (X.509 extension) */
        self.critical = true;
        self.data = build_key_usage(bits);
        self
    }

    pub fn build(self) -> X509Ext {
        X509Ext {
            oid: self.oid,
            critical: self.critical,
            data: self.data,
        }
    }
}

fn parse_key_usage_bits(b: &[u8]) -> Option<Vec<X509KeyUsage>> {
    let mut bits = Vec::new();

    if b.get(0)? & (1 << 7) != 0 {
        bits.push(X509KeyUsage::DigitalSignature);
    }
    if b.get(0)? & (1 << 6) != 0 {
        bits.push(X509KeyUsage::NonRepudiation);
    }
    if b.get(0)? & (1 << 5) != 0 {
        bits.push(X509KeyUsage::KeyEncipherment);
    }
    if b.get(0)? & (1 << 4) != 0 {
        bits.push(X509KeyUsage::DataEncipherment);
    }
    if b.get(0)? & (1 << 3) != 0 {
        bits.push(X509KeyUsage::KeyAgreement);
    }
    if b.get(0)? & (1 << 2) != 0 {
        bits.push(X509KeyUsage::KeyCertSign);
    }
    if b.get(0)? & (1 << 1) != 0 {
        bits.push(X509KeyUsage::CRLSign);
    }
    if b.get(0)? & (1 << 0) != 0 {
        bits.push(X509KeyUsage::EncipherOnly);
    }
    if b.len() > 1 && b.get(1)? & (1 << 7) != 0 {
        bits.push(X509KeyUsage::DecipherOnly);
    }

    Some(bits)
}

fn parse_key_usage(data: &[u8]) -> Result<Vec<X509KeyUsage>, Error> {
    let asn = simple_asn1::from_der(data).map_err(Error::KeyUsage)?;
    let b = match asn.get(0).ok_or(Error::KeyUsageIdx0)? {
        ASN1Block::BitString(_, _, b) => b,
        _ => return Err(Error::KeyUsageBits),
    };

    parse_key_usage_bits(b).ok_or(Error::KeyUsageIdx1)
}

pub trait X509ExtDeserialize {
    fn key_usage(&self) -> Result<Vec<X509KeyUsage>, Error>;
}

impl X509ExtDeserialize for Vec<X509Ext> {
    fn key_usage(&self) -> Result<Vec<X509KeyUsage>, Error> {
        for e in self.iter() {
            if e.oid == vec![2, 5, 29, 15] {
                return parse_key_usage(&e.data);
            }
        }

        Err(Error::ExtDeserialize)
    }
}
