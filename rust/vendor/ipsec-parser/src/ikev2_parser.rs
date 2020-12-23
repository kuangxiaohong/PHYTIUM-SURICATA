use crate::error::IPsecError;
use crate::ikev2::*;
use crate::ikev2_notify::NotifyType;
use crate::ikev2_transforms::*;
use nom::error::ErrorKind;
use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use nom::IResult;

named! {pub parse_ikev2_header<IkeV2Header>,
    do_parse!(
        init_spi: be_u64 >>
        resp_spi: be_u64 >>
        np:       be_u8 >>
        vers: bits!(
            tuple!(take_bits!(4u8),take_bits!(4u8))
        ) >>
        ex:       be_u8 >>
        flags:    be_u8 >>
        id:       be_u32 >>
        l:        be_u32 >>
        (
            IkeV2Header {
                init_spi,
                resp_spi,
                next_payload: IkePayloadType(np),
                maj_ver: vers.0,
                min_ver: vers.1,
                exch_type: IkeExchangeType(ex),
                flags,
                msg_id: id,
                length: l,
            }
        )
    )
}

// not written inside do_parse, else compiler has trouble inferring types
#[inline]
fn bits_split_1(i: &[u8]) -> IResult<&[u8], (u8, u8)> {
    bits!(i, pair!(take_bits!(1u8), take_bits!(7u8)))
}

named! {pub parse_ikev2_payload_generic<IkeV2GenericPayload>,
    do_parse!(
        np_type: be_u8 >>
        b:       bits_split_1 >>
        len:     be_u16 >>
                 error_if!(len < 4, ErrorKind::Verify) >>
        data:    take!(len - 4) >>
        (
            IkeV2GenericPayload{
                hdr: IkeV2PayloadHeader {
                    next_payload_type: IkePayloadType(np_type),
                    critical: b.0 == 1,
                    reserved: b.1,
                    payload_length: len,
                },
                payload: data,
            }
        )
    )
}

named! {pub parse_ikev2_transform<IkeV2RawTransform>,
    do_parse!(
        last:             be_u8 >>
        reserved1:        be_u8 >>
        transform_length: be_u16 >>
        transform_type:   be_u8 >>
        reserved2:        be_u8 >>
        transform_id:     be_u16 >>
        attributes:       cond!(transform_length > 8,take!(transform_length-8)) >>
        (
            IkeV2RawTransform{
                last: last,
                reserved1:reserved1,
                transform_length: transform_length,
                transform_type: IkeTransformType(transform_type),
                reserved2: reserved2,
                transform_id: transform_id,
                attributes: attributes,
            }
        )
    )
}

named! {pub parse_ikev2_proposal<IkeV2Proposal>,
    do_parse!(
       last:           be_u8 >>
       reserved:       be_u8 >>
       p_len:          be_u16 >>
       p_num:          be_u8 >>
       proto_id:       be_u8 >>
       spi_size:       be_u8 >>
       num_transforms: be_u8 >>
       spi:            cond!(spi_size > 0,take!(spi_size)) >>
                       error_if!(p_len < (8u16+spi_size as u16), ErrorKind::Verify) >>
       transforms:     flat_map!(
            take!( p_len - (8u16+spi_size as u16) ),
            count!(parse_ikev2_transform, num_transforms as usize)
            ) >>
        ( IkeV2Proposal{
            last,
            reserved,
            proposal_length: p_len,
            proposal_num: p_num,
            protocol_id: ProtocolID(proto_id),
            spi_size,
            num_transforms,
            spi,
            transforms,
        })
    )
}

pub fn parse_ikev2_payload_sa<'a>(
    i: &'a [u8],
    _length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, many1!(complete!(parse_ikev2_proposal)), |v| {
        IkeV2PayloadContent::SA(v)
    })
}

pub fn parse_ikev2_payload_kex<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        dh:       be_u16 >>
        reserved: be_u16 >>
                  error_if!(length < 4, ErrorKind::Verify) >>
        kex_data: take!(length-4) >>
        (
            IkeV2PayloadContent::KE(
                KeyExchangePayload{
                    dh_group: IkeTransformDHType(dh),
                    reserved,
                    kex_data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_ident_init<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        id_type:   be_u8 >>
        reserved1: be_u8 >>
        reserved2: be_u16 >>
                   error_if!(length < 4, ErrorKind::Verify) >>
        data:      take!(length-4) >>
        (
            IkeV2PayloadContent::IDi(
                IdentificationPayload{
                    id_type: IdentificationType(id_type),
                    reserved1: reserved1,
                    reserved2: reserved2,
                    ident_data: data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_ident_resp<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        id_type:   be_u8 >>
        reserved1: be_u8 >>
        reserved2: be_u16 >>
                   error_if!(length < 4, ErrorKind::Verify) >>
        data:      take!(length-4) >>
        (
            IkeV2PayloadContent::IDr(
                IdentificationPayload{
                    id_type: IdentificationType(id_type),
                    reserved1,
                    reserved2,
                    ident_data: data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_certificate<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        encoding: be_u8 >>
                  error_if!(length < 1, ErrorKind::Verify) >>
        data:     take!(length-1) >>
        (
            IkeV2PayloadContent::Certificate(
                CertificatePayload{
                    cert_encoding: CertificateEncoding(encoding),
                    cert_data: data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_certificate_request<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        encoding: be_u8 >>
                  error_if!(length < 1, ErrorKind::Verify) >>
        data:     take!(length-1) >>
        (
            IkeV2PayloadContent::CertificateRequest(
                CertificateRequestPayload{
                    cert_encoding: CertificateEncoding(encoding),
                    ca_data: data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_authentication<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        method: be_u8 >>
                error_if!(length < 4, ErrorKind::Verify) >>
        data:   take!(length-4) >>
        (
            IkeV2PayloadContent::Authentication(
                AuthenticationPayload{
                    auth_method: AuthenticationMethod(method),
                    auth_data:   data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_nonce<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        data: take!(length) >>
        (
            IkeV2PayloadContent::Nonce(
                NoncePayload{
                    nonce_data: data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_notify<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        proto_id:    be_u8 >>
        spi_size:    be_u8 >>
        notify_type: be_u16 >>
        spi:         cond!(spi_size > 0, take!(spi_size)) >>
        notify_data: cond!(length > 8 + spi_size as u16, take!(length-(8+spi_size as u16))) >>
        (
            IkeV2PayloadContent::Notify(
                NotifyPayload{
                    protocol_id: ProtocolID(proto_id),
                    spi_size,
                    notify_type: NotifyType(notify_type),
                    spi,
                    notify_data,
                }
            )
        )
    }
}

pub fn parse_ikev2_payload_vendor_id<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
                   error_if!(length < 8, ErrorKind::Verify) >>
        vendor_id: take!(length-8) >>
        (
            IkeV2PayloadContent::VendorID(
                VendorIDPayload{ vendor_id }
            )
        )
    }
}

pub fn parse_ikev2_payload_delete<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    do_parse! {
        i,
        proto_id:   be_u8 >>
        spi_size:   be_u8 >>
        num_spi:    be_u16 >>
                    error_if!(length < 8, ErrorKind::Verify) >>
        spi:        take!(length-8) >>
        (
            IkeV2PayloadContent::Delete(
                DeletePayload{
                    protocol_id: ProtocolID(proto_id),
                    spi_size,
                    num_spi,
                    spi,
                }
            )
        )
    }
}

fn parse_ts_addr<'a>(i: &'a [u8], t: u8) -> IResult<&'a [u8], &'a [u8]> {
    match t {
        7 => take!(i, 4),
        8 => take!(i, 16),
        _ => Err(nom::Err::Error(error_position!(i, ErrorKind::Switch))),
    }
}

fn parse_ikev2_ts<'a>(i: &'a [u8]) -> IResult<&'a [u8], TrafficSelector<'a>> {
    do_parse! {
        i,
        ts_type:     be_u8 >>
        ip_proto_id: be_u8 >>
        sel_length:  be_u16 >>
        start_port:  be_u16 >>
        end_port:    be_u16 >>
        start_addr:  call!(parse_ts_addr,ts_type) >>
        end_addr:    call!(parse_ts_addr,ts_type) >>
        (
            TrafficSelector{
                ts_type: TSType(ts_type),
                ip_proto_id,
                sel_length,
                start_port,
                end_port,
                start_addr,
                end_addr,
            }
        )
    }
}

pub fn parse_ikev2_payload_ts<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], TrafficSelectorPayload<'a>> {
    do_parse! {
        i,
        num_ts:   be_u8 >>
        reserved: take!(3) >>
                  error_if!(length < 4, ErrorKind::Verify) >>
        ts:       flat_map!(take!(length-4),
            many1!(complete!(parse_ikev2_ts))
        ) >>
        (
            TrafficSelectorPayload{ num_ts, reserved, ts }
        )
    }
}

pub fn parse_ikev2_payload_ts_init<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, call!(parse_ikev2_payload_ts, length), |x| {
        IkeV2PayloadContent::TSi(x)
    })
}

pub fn parse_ikev2_payload_ts_resp<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, call!(parse_ikev2_payload_ts, length), |x| {
        IkeV2PayloadContent::TSr(x)
    })
}

pub fn parse_ikev2_payload_unknown<'a>(
    i: &'a [u8],
    length: u16,
) -> IResult<&'a [u8], IkeV2PayloadContent<'a>> {
    map!(i, take!(length), |d| { IkeV2PayloadContent::Unknown(d) })
}

#[rustfmt::skip]
pub fn parse_ikev2_payload_with_type(
    i: &[u8],
    length: u16,
    next_payload_type: IkePayloadType,
) -> IResult<&[u8], IkeV2PayloadContent> {
    let f = match next_payload_type {
        // IkePayloadType::NoNextPayload       => parse_ikev2_payload_unknown, // XXX ?
        IkePayloadType::SecurityAssociation      => parse_ikev2_payload_sa,
        IkePayloadType::KeyExchange              => parse_ikev2_payload_kex,
        IkePayloadType::IdentInitiator           => parse_ikev2_payload_ident_init,
        IkePayloadType::IdentResponder           => parse_ikev2_payload_ident_resp,
        IkePayloadType::Certificate              => parse_ikev2_payload_certificate,
        IkePayloadType::CertificateRequest       => parse_ikev2_payload_certificate_request,
        IkePayloadType::Authentication           => parse_ikev2_payload_authentication,
        IkePayloadType::Nonce                    => parse_ikev2_payload_nonce,
        IkePayloadType::Notify                   => parse_ikev2_payload_notify,
        IkePayloadType::Delete                   => parse_ikev2_payload_delete,
        IkePayloadType::VendorID                 => parse_ikev2_payload_vendor_id,
        IkePayloadType::TrafficSelectorInitiator => parse_ikev2_payload_ts_init,
        IkePayloadType::TrafficSelectorResponder => parse_ikev2_payload_ts_resp,
        // None                                               => parse_ikev2_payload_unknown,
        _ => parse_ikev2_payload_unknown,
        // _ => panic!("unknown type {}",next_payload_type),
    };
    flat_map!(i,take!(length),call!(f,length))
}

fn parse_ikev2_payload_list_fold<'a>(
    res_v: Result<Vec<IkeV2Payload<'a>>, IPsecError>,
    p: IkeV2GenericPayload<'a>,
) -> Result<Vec<IkeV2Payload<'a>>, IPsecError> {
    let mut v = res_v?;
    // println!("parse_payload_list_fold: v.len={} p={:?}",v.len(),p);
    assert!(v.len() > 0);
    let last_payload = v
        .last()
        .expect("parse_payload_list_fold: called with empty input");
    let next_payload_type = last_payload.hdr.next_payload_type;
    if p.hdr.payload_length < 4 {
        return Err(IPsecError::PayloadTooSmall);
    }
    match parse_ikev2_payload_with_type(p.payload, p.hdr.payload_length - 4, next_payload_type) {
        Ok((rem, p2)) => {
            // let (rem, p2) = parse_ikev2_payload_with_type(p.payload, p.hdr.payload_length - 4, next_payload_type)?;
            if rem.len() != 0 {
                return Err(IPsecError::ExtraBytesInPayload); // XXX should this be only a warning?
            }
            let payload = IkeV2Payload {
                hdr: p.hdr.clone(),
                content: p2,
            };
            v.push(payload);
            Ok(v)
        }
        Err(nom::Err::Error((_, e))) | Err(nom::Err::Failure((_, e))) => {
            Err(IPsecError::NomError(e))
        }
        Err(nom::Err::Incomplete(_)) => Err(IPsecError::NomError(ErrorKind::Complete)),
    }
}

pub fn parse_ikev2_payload_list<'a>(
    i: &'a [u8],
    initial_type: IkePayloadType,
) -> IResult<&'a [u8], Result<Vec<IkeV2Payload<'a>>, IPsecError>> {
    // XXX fold manually, because fold_many1 requires accumulator to have Clone, and we don't want
    // XXX to implement that for IkeV2Payload
    let mut acc = Ok(vec![IkeV2Payload {
        hdr: IkeV2PayloadHeader {
            next_payload_type: initial_type,
            critical: false,
            reserved: 0,
            payload_length: 0,
        },
        content: IkeV2PayloadContent::Dummy,
    }]);
    let mut i = i.clone();
    loop {
        if i.len() == 0 {
            break;
        }

        let (rem, p) = complete!(i, parse_ikev2_payload_generic)?;

        acc = parse_ikev2_payload_list_fold(acc, p);

        i = rem;
    }
    Ok((i, acc))
    // XXX should we split_first() the vector and return all but the first element ?
}

/// Parse an IKEv2 message
///
/// Parse the IKEv2 header and payload list
pub fn parse_ikev2_message<'a>(
    i: &[u8],
) -> IResult<&[u8], (IkeV2Header, Result<Vec<IkeV2Payload>, IPsecError>)> {
    do_parse! {
        i,
        hdr: parse_ikev2_header >>
             error_if!(hdr.length < 28, ErrorKind::Verify) >>
        // copy values, flat_map moves values
        l:   q!(hdr.length) >>
        n:   q!(hdr.next_payload) >>
        msg: flat_map!(
                take!(l - 28),
                call!(parse_ikev2_payload_list, n)
            ) >>
        (hdr, msg)
    }
}

#[cfg(test)]
mod tests {
    use crate::ikev2_parser::*;

    #[rustfmt::skip]
static IKEV2_INIT_REQ: &'static [u8] = &[
    0x01, 0xf8, 0xc3, 0xd4, 0xbb, 0x77, 0x3f, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x22, 0x00, 0x00, 0x30,
    0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14,
    0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, 0x03, 0x00, 0x00, 0x08,
    0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1e, 0x28, 0x00, 0x00, 0x88,
    0x00, 0x1e, 0x00, 0x00, 0x8f, 0xe6, 0xf3, 0x6e, 0x88, 0x7b, 0x18, 0x9b, 0x5e, 0xce, 0xf2, 0x56,
    0xf9, 0x8d, 0x76, 0xaa, 0xcb, 0x07, 0xb3, 0xb9, 0x58, 0xee, 0x73, 0xea, 0x7b, 0x73, 0xb1, 0x04,
    0x7e, 0xa4, 0x2a, 0x4e, 0x44, 0x1f, 0xb9, 0x3e, 0xf9, 0xa9, 0xab, 0x0c, 0x54, 0x5a, 0xa7, 0x46,
    0x2e, 0x58, 0x3c, 0x06, 0xb2, 0xed, 0x91, 0x8d, 0x11, 0xca, 0x67, 0xdb, 0x21, 0x6b, 0xb8, 0xad,
    0xbf, 0x57, 0x3f, 0xba, 0x5a, 0xa6, 0x7d, 0x49, 0x83, 0x4b, 0xa9, 0x93, 0x6f, 0x4c, 0xe9, 0x66,
    0xcd, 0x57, 0x5c, 0xba, 0x07, 0x42, 0xfa, 0x0b, 0xe8, 0xb9, 0xd0, 0x25, 0xc4, 0xb9, 0xdf, 0x29,
    0xd7, 0xe4, 0x6e, 0xd6, 0x54, 0x78, 0xaa, 0x95, 0x02, 0xbf, 0x25, 0x55, 0x71, 0xfa, 0x9e, 0xcb,
    0x05, 0xea, 0x8f, 0x7b, 0x14, 0x0e, 0x1d, 0xdf, 0xb4, 0x03, 0x5f, 0x2d, 0x21, 0x66, 0x58, 0x6e,
    0x42, 0x72, 0x32, 0x03, 0x29, 0x00, 0x00, 0x24, 0xe3, 0x3b, 0x52, 0xaa, 0x6f, 0x6d, 0x62, 0x87,
    0x16, 0xd7, 0xab, 0xc6, 0x45, 0xa6, 0xcc, 0x97, 0x07, 0x43, 0x3d, 0x85, 0x83, 0xde, 0xab, 0x97,
    0xdb, 0xbf, 0x08, 0xce, 0x0f, 0xad, 0x59, 0x71, 0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x04,
    0xcc, 0xc0, 0x64, 0x5c, 0x1e, 0xeb, 0xc2, 0x1d, 0x09, 0x2b, 0xf0, 0x7f, 0xca, 0x34, 0xc3, 0xe6,
    0x2b, 0x20, 0xec, 0x8f, 0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x05, 0x15, 0x39, 0x75, 0x77,
    0xf5, 0x54, 0x87, 0xa3, 0x8f, 0xd8, 0xaf, 0x70, 0xb0, 0x9c, 0x20, 0x9c, 0xff, 0x4a, 0x37, 0xd1,
    0x29, 0x00, 0x00, 0x10, 0x00, 0x00, 0x40, 0x2f, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x16
];

    #[test]
    fn test_ikev2_init_req() {
        let empty = &b""[..];
        let bytes = &IKEV2_INIT_REQ[0..28];
        let expected = Ok((
            empty,
            IkeV2Header {
                init_spi: 0x01f8c3d4bb773f2f,
                resp_spi: 0x0,
                next_payload: IkePayloadType::SecurityAssociation,
                maj_ver: 2,
                min_ver: 0,
                exch_type: IkeExchangeType::IKE_SA_INIT,
                flags: 0x8,
                msg_id: 0,
                length: 328,
            },
        ));
        let res = parse_ikev2_header(&bytes);
        assert_eq!(res, expected);
    }

    static IKEV2_INIT_RESP: &'static [u8] = include_bytes!("../assets/ike-sa-init-resp.bin");

    #[test]
    fn test_ikev2_init_resp() {
        let bytes = IKEV2_INIT_RESP;
        let (rem, ref hdr) = parse_ikev2_header(&bytes).expect("parsing header failed");
        let (rem2, res_p) =
            parse_ikev2_payload_list(rem, hdr.next_payload).expect("parsing payload failed");
        assert!(rem2.is_empty());
        let p = res_p.expect("parsing payload failed");
        // there are 5 items + dummy => 6
        assert_eq!(p.len(), 6);
        // first one is always dummy
        assert_eq!(p[0].content, IkeV2PayloadContent::Dummy);
    }

    #[rustfmt::skip]
static IKEV2_PAYLOAD_SA: &'static [u8] = &[
    0x22, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x0c,
    0x01, 0x00, 0x00, 0x14, 0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1e
];

    #[test]
    fn test_ikev2_payload_sa() {
        let bytes = IKEV2_PAYLOAD_SA;
        let expected1 = IkeV2GenericPayload {
            hdr: IkeV2PayloadHeader {
                next_payload_type: IkePayloadType::KeyExchange,
                critical: false,
                reserved: 0,
                payload_length: 40,
            },
            payload: &bytes[4..],
        };
        let (_, res) = parse_ikev2_payload_generic(&bytes).expect("Failed to parse");
        assert_eq!(res, expected1);
        let attrs1 = &[0x80, 0x0e, 0x00, 0x80];
        let expected2 = IkeV2PayloadContent::SA(vec![IkeV2Proposal {
            last: 0,
            reserved: 0,
            proposal_length: 36,
            proposal_num: 1,
            protocol_id: ProtocolID::IKE,
            spi_size: 0,
            num_transforms: 3,
            spi: None,
            transforms: vec![
                IkeV2RawTransform {
                    last: 3,
                    reserved1: 0,
                    transform_length: 12,
                    transform_type: IkeTransformType::EncryptionAlgorithm,
                    reserved2: 0,
                    transform_id: 20,
                    attributes: Some(attrs1),
                },
                IkeV2RawTransform {
                    last: 3,
                    reserved1: 0,
                    transform_length: 8,
                    transform_type: IkeTransformType::PseudoRandomFunction,
                    reserved2: 0,
                    transform_id: 5,
                    attributes: None,
                },
                IkeV2RawTransform {
                    last: 0,
                    reserved1: 0,
                    transform_length: 8,
                    transform_type: IkeTransformType::DiffieHellmanGroup,
                    reserved2: 0,
                    transform_id: 30,
                    attributes: None,
                },
            ],
        }]);

        let (rem, res2) = parse_ikev2_payload_sa(res.payload, 0).expect("Failed to parse");
        assert!(rem.is_empty());
        assert_eq!(res2, expected2);
    }

    #[test]
    fn test_ikev2_parse_payload_many() {
        // let empty = &b""[..];
        let bytes = &IKEV2_INIT_REQ[28..];
        let res = parse_ikev2_payload_list(&bytes, IkePayloadType::SecurityAssociation);
        println!("{:?}", res);
    }

}
