use simple_asn1::ASN1Block;

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

impl X509Ext {
    pub fn builder() -> X509ExtBuilder {
        X509ExtBuilder::default()
    }

    fn build_key_usage(bits: Vec<X509KeyUsage>) -> Vec<u8> {
        let mut b: Vec<u8> = vec![0];
        let mut n: usize = 0;

        for i in 0..bits.len() {
            match bits[i] {
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
        self.data = X509Ext::build_key_usage(bits);
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
