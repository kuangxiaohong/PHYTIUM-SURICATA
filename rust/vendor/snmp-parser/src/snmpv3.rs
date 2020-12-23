//! SNMPv3 Parser
//!
//! SNMPv3 is defined in the following RFCs:
//!   - [RFC2570](https://tools.ietf.org/html/rfc2570): Introduction to SNMP v3
//!   - [RFC3412](https://tools.ietf.org/html/rfc3412): Message Processing and Dispatching for the
//!     Simple Network Management Protocol (SNMP)
//!
//! See also:
//!   - [RFC2578](https://tools.ietf.org/html/rfc2578): Structure of Management Information Version 2 (SMIv2)

use std::fmt;

use der_parser::ber::*;
use der_parser::error::*;
use nom::IResult;

use crate::snmp::{SnmpPdu, parse_ber_octetstring_as_slice, parse_snmp_v2c_pdu};
pub use crate::usm::{UsmSecurityParameters,parse_usm_security_parameters};
use crate::error::SnmpError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecurityModel(pub u32);

#[allow(non_upper_case_globals)]
impl SecurityModel {
    pub const SnmpV1    : SecurityModel = SecurityModel(1);
    pub const SnmpV2c   : SecurityModel = SecurityModel(2);
    pub const USM       : SecurityModel = SecurityModel(3);
}

impl fmt::Debug for SecurityModel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
           1 => f.write_str("SnmpV1"),
           2 => f.write_str("SnmpV2c"),
           3 => f.write_str("USM"),
           n => f.debug_tuple("SecurityModel").field(&n).finish(),
        }
    }
}

#[derive(Debug,PartialEq)]
pub enum SecurityParameters<'a> {
    Raw(&'a[u8]),
    USM(UsmSecurityParameters<'a>)
}

/// An SNMPv3 message
#[derive(Debug,PartialEq)]
pub struct SnmpV3Message<'a> {
    /// Version, as raw-encoded: 3 for SNMPv3
    pub version: u32,
    pub header_data: HeaderData,
    pub security_params: SecurityParameters<'a>,
    pub data: ScopedPduData<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HeaderData {
    pub msg_id: u32,
    pub msg_max_size: u32,
    pub msg_flags: u8,
    pub msg_security_model: SecurityModel,
}

impl HeaderData {
    pub fn is_authenticated(&self) -> bool { self.msg_flags & 0b001 != 0 }

    pub fn is_encrypted(&self) -> bool { self.msg_flags & 0b010 != 0 }

    pub fn is_reportable(&self) -> bool { self.msg_flags & 0b100 != 0 }
}

#[derive(Debug,PartialEq)]
pub enum ScopedPduData<'a> {
    Plaintext(ScopedPdu<'a>),
    Encrypted(&'a[u8]),
}

#[derive(Debug,PartialEq)]
pub struct ScopedPdu<'a> {
    pub ctx_engine_id: &'a[u8],
    pub ctx_engine_name: &'a[u8],
    /// ANY -- e.g., PDUs as defined in [RFC3416](https://tools.ietf.org/html/rfc3416)
    pub data: SnmpPdu<'a>,
}




pub(crate) fn parse_snmp_v3_data<'a>(i:&'a[u8], hdr: &HeaderData) -> IResult<&'a[u8], ScopedPduData<'a>, BerError> {
    if hdr.is_encrypted()
    {
        map_res!(i,
                 parse_ber_octetstring,
                 |x: BerObject<'a>| x.as_slice().map(|x| ScopedPduData::Encrypted(x))
        )
    } else {
        parse_snmp_v3_plaintext_pdu(i)
    }
}

pub(crate) fn parse_secp<'a>(x:&BerObject<'a>, hdr:&HeaderData) -> Result<SecurityParameters<'a>, BerError> {
    match x.as_slice() {
        Ok(i) => {
            match hdr.msg_security_model {
                SecurityModel::USM => {
                    match parse_usm_security_parameters(i) {
                        Ok((_,usm)) => Ok(SecurityParameters::USM(usm)),
                        _           => Err(BerError::BerValueError)
                    }
                },
                _                  => Ok(SecurityParameters::Raw(i))
            }
        },
        _     => Err(BerError::BerValueError)
    }
}

/// Parse an SNMPv3 top-level message
///
/// Example:
///
/// ```rust
/// # extern crate nom;
/// # #[macro_use] extern crate snmp_parser;
/// use snmp_parser::{parse_snmp_v3,ScopedPduData,SecurityModel};
///
/// static SNMPV3_REQ: &'static [u8] = include_bytes!("../assets/snmpv3_req.bin");
///
/// # fn main() {
/// match parse_snmp_v3(&SNMPV3_REQ) {
///   Ok((_, ref r)) => {
///     assert!(r.version == 3);
///     assert!(r.header_data.msg_security_model == SecurityModel::USM);
///     match r.data {
///       ScopedPduData::Plaintext(ref _pdu) => { },
///       ScopedPduData::Encrypted(_) => (),
///     }
///   },
///   Err(e) => panic!(e),
/// }
/// # }
/// ```
pub fn parse_snmp_v3<'a>(i:&'a[u8]) -> IResult<&'a[u8], SnmpV3Message<'a>, SnmpError> {
    upgrade_error! {
        parse_der_struct!(
            i,
            TAG BerTag::Sequence,
            vers: parse_ber_u32 >>
            hdr:  parse_snmp_v3_headerdata >>
            secp: map_res!(parse_ber_octetstring, |x: BerObject<'a>| parse_secp(&x,&hdr)) >>
            data: call!(parse_snmp_v3_data,&hdr) >>
            ({
                SnmpV3Message{
                    version: vers,
                    header_data: hdr,
                    security_params: secp,
                    data
                }
            })
        )
        .map(|(rem,x)| (rem,x.1))
    }
}

pub(crate) fn parse_snmp_v3_headerdata(i:&[u8]) -> IResult<&[u8], HeaderData, BerError> {
    parse_der_struct!(
        i,
        TAG BerTag::Sequence,
        id: parse_ber_u32 >>
        sz: parse_ber_u32 >>
        fl: map_res!(parse_ber_octetstring, |x: BerObject| x.as_slice().and_then(|s|
            if s.len() == 1 { Ok(s[0]) } else { Err(BerError::BerValueError) })) >>
        sm: parse_ber_u32 >>
        (
            HeaderData{
                msg_id: id,
                msg_max_size: sz,
                msg_flags: fl,
                msg_security_model: SecurityModel(sm),
            }
        )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_snmp_v3_plaintext_pdu(i:&[u8]) -> IResult<&[u8], ScopedPduData, BerError> {
    parse_der_struct!(
        i,
        ctx_eng_id: parse_ber_octetstring_as_slice >>
        ctx_name:   parse_ber_octetstring_as_slice >>
        data:       parse_snmp_v2c_pdu >>
        (
            ScopedPduData::Plaintext(ScopedPdu{
                ctx_engine_id: ctx_eng_id,
                ctx_engine_name: ctx_name,
                data
            })
        )
    ).map(|(rem,x)| (rem,x.1))
}
