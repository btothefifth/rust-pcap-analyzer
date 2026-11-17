//! Bounded summaries carried to the end of the correlation window. Payload
//! values remain in the original observations, including write and echo data.
use super::{
    pdu::{self, Pdu},
    Role,
};
use crate::{json::Json, sha256};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Summary {
    Read {
        function: u8,
        start: u16,
        count: u16,
    },
    Data {
        function: u8,
        bytes: u16,
        last: u8,
    },
    Write(u8, u16, u16),
    FileEcho([[u8; 32]; 4]),
    Mask(u16, u16, u16),
    FileLengths(Vec<u16>),
    DeviceRequest(u8, u8),
    DevicePage(u8, Vec<u8>),
    Fifo,
    Exception,
}

impl Summary {
    pub(super) fn parse(bytes: &[u8], role: Role) -> Option<Self> {
        if !pdu::supported(bytes) {
            return None;
        }
        let pdu = pdu::parse(bytes, role).ok()?;
        Self::from_pdu(bytes, &pdu)
    }

    pub(crate) fn from_pdu(bytes: &[u8], pdu: &Pdu) -> Option<Self> {
        if !pdu.complete() {
            return None;
        }
        Some(match pdu {
            Pdu::Read { start, count } | Pdu::ReadWrite { start, count, .. } => Self::Read {
                function: bytes[0],
                start: *start,
                count: *count,
            },
            Pdu::ReadData(len) => Self::Data {
                function: bytes[0],
                bytes: *len as u16,
                last: if bytes[0] <= 2 { *bytes.last()? } else { 0 },
            },
            Pdu::Mask => Self::Mask(
                super::be16(&bytes[1..3]),
                super::be16(&bytes[3..5]),
                super::be16(&bytes[5..7]),
            ),
            Pdu::Single => Self::Write(
                bytes[0],
                super::be16(&bytes[1..3]),
                super::be16(&bytes[3..5]),
            ),
            Pdu::Multiple { start, count, .. } | Pdu::WriteAck { start, count } => {
                Self::Write(bytes[0], *start, *count)
            }
            Pdu::FifoRequest | Pdu::FifoData(_) => Self::Fifo,
            Pdu::Files(records, _) if bytes[0] == 20 => {
                Self::FileLengths(records.iter().map(|r| r.words).collect())
            }
            Pdu::Files(records, _) => {
                let mut columns: [sha256::Sha256; 4] = Default::default();
                for r in records {
                    let (file, record) = r.address?;
                    columns[0].update(&file.to_be_bytes());
                    columns[1].update(&record.to_be_bytes());
                    columns[2].update(&r.words.to_be_bytes());
                    let pos = r.offset + 7;
                    columns[3].update(&bytes[pos..pos + r.data_len]);
                }
                Self::FileEcho(columns.map(|column| column.finalize()))
            }
            Pdu::DeviceRequest => Self::DeviceRequest(bytes[2], bytes[3]),
            Pdu::DevicePage(objects, _) => Self::DevicePage(
                bytes[2],
                objects
                    .iter()
                    .map(|o| o.id)
                    .chain((bytes[4] != 0).then_some(bytes[5]))
                    .collect(),
            ),
            Pdu::Exception(_) => Self::Exception,
            Pdu::Opaque => return None,
        })
    }

    pub(crate) fn agrees(&self, response: &Self) -> bool {
        match (self, response) {
            (_, Self::Exception) => true,
            (
                Self::Read {
                    function, count, ..
                },
                Self::Data {
                    function: f,
                    bytes,
                    last,
                },
            ) => {
                function == f
                    && match function {
                        1 | 2 => bits_match(*count, *bytes, (*last).into()),
                        3 | 4 | 23 => (1..=125).contains(count) && *bytes == 2 * count,
                        _ => false,
                    }
            }
            (Self::DeviceRequest(category, id), Self::DevicePage(c, i)) => {
                c == category && device_start_matches(*category, *id, i)
            }
            (
                Self::Mask(..)
                | Self::Write(..)
                | Self::FileEcho(_)
                | Self::FileLengths(_)
                | Self::Fifo,
                _,
            ) => self == response,
            _ => false,
        }
    }

    pub(crate) fn token(self) -> String {
        let value = match self {
            Self::Read {
                function,
                start,
                count,
            } => format!("read:{function}:{start}:{count}"),
            Self::Data {
                function,
                bytes,
                last,
            } => format!("data:{function}:{bytes}:{last}"),
            Self::DeviceRequest(c, id) => format!("id-request:{c}:{id}"),
            Self::DevicePage(c, ids) => format!("id-page:{c}:{}", sha256::hex(&ids)),
            Self::Mask(a, m, o) => format!("mask:{a}:{m}:{o}"),
            Self::Write(f, address, value) => format!("write:{f}:{address}:{value}"),
            Self::FileEcho(columns) => format!(
                "file-echo:{}",
                columns.map(|hash| sha256::hex(&hash)).join(":")
            ),
            Self::FileLengths(counts) => format!(
                "file:{}",
                counts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::Fifo => "fifo".into(),
            Self::Exception => String::new(),
        };
        format!("modbus-pdu-v2:{value}")
    }
}
pub fn correlation_token(bytes: &[u8], role: Role) -> Option<String> {
    Some(Summary::parse(bytes, role)?.token())
}
fn parts<const N: usize>(token: &str, prefix: &str) -> Option<[u16; N]> {
    let mut fields = token.strip_prefix(prefix)?.split(':');
    let mut nums = [0; N];
    for n in &mut nums {
        *n = fields.next()?.parse().ok()?;
    }
    fields.next().is_none().then_some(nums)
}
fn device_start_matches(category: u8, requested: u8, ids: &[u8]) -> bool {
    ids.first() == Some(&requested)
        || (category != 4 && requested > 2 && ids.first() == Some(&0) && !ids.contains(&requested))
}
fn device_fields(request: &str, response: &str) -> Option<(bool, bool)> {
    let [category, id] = parts(request, "id-request:")?;
    let (peer, encoded) = response.strip_prefix("id-page:")?.split_once(':')?;
    if encoded.len() > 510 || encoded.len() % 2 != 0 || !encoded.is_ascii() {
        return None;
    }
    let ids = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((
        peer.parse::<u16>().ok()? == category,
        device_start_matches(category.try_into().ok()?, id.try_into().ok()?, &ids),
    ))
}
fn bits_match(count: u16, bytes: u16, last: u16) -> bool {
    (1..=2000).contains(&count)
        && bytes == count.div_ceil(8)
        && last <= 255
        && (count % 8 == 0 || last >> (count % 8) == 0)
}
pub(crate) fn matches(request: &str, response: &str) -> bool {
    if request.is_empty() || response.is_empty() {
        return true;
    }
    if let (Some(request), Some(response)) = (
        request.strip_prefix("modbus-pdu-v2:"),
        response.strip_prefix("modbus-pdu-v2:"),
    ) {
        return response.is_empty() || matches_v2(request, response);
    }
    if request.starts_with("modbus-pdu-v2:") || response.starts_with("modbus-pdu-v2:") {
        return false;
    }
    if request.starts_with("modbus-bits-v1:") || response.starts_with("modbus-bits-v1:") {
        return parts(request, "modbus-bits-v1:quantity:")
            .zip(parts(response, "modbus-bits-v1:response:"))
            .is_some_and(|([q], [n, last])| bits_match(q, n, last));
    }
    request == response
}
fn matches_v2(request: &str, response: &str) -> bool {
    if let Some([f, _, count]) = parts(request, "read:") {
        let Some([g, n, last]) = parts(response, "data:") else {
            return false;
        };
        let (Ok(function), Ok(peer), Ok(last)) =
            (u8::try_from(f), u8::try_from(g), u8::try_from(last))
        else {
            return false;
        };
        return Summary::Read {
            function,
            start: 0,
            count,
        }
        .agrees(&Summary::Data {
            function: peer,
            bytes: n,
            last,
        });
    }
    if request.starts_with("id-request:") {
        return device_fields(request, response) == Some((true, true));
    }
    request == response
}

/// Compact mapping for every meaningful response value in a finalized pair.
/// Both witness references resolve into the original message's ADU and spans.
pub fn pair_projection(
    request: &str,
    response: &str,
    status: &str,
    request_ref: Json,
    response_ref: Json,
) -> Option<Json> {
    let [function, start, count] = parts(request, "modbus-pdu-v2:read:")?;
    if !response.starts_with("modbus-pdu-v2:data:") || !matches(request, response) {
        return None;
    }
    let bits = function <= 2;
    Some(Json::object([
        ("status", status.into()),
        ("request", request_ref),
        ("response", response_ref),
        ("starting_address_zero_based", start.into()),
        ("quantity", count.into()),
        ("request_address_adu_offset", 8u8.into()),
        ("request_quantity_adu_offset", 10u8.into()),
        ("response_values_adu_offset", 9u8.into()),
        (
            "value_layout",
            if bits {
                "lsb_first_bits"
            } else {
                "big_endian_u16"
            }
            .into(),
        ),
        (
            "address_rule",
            "starting_address_plus_zero_based_value_index".into(),
        ),
        ("padding_checked", bits.into()),
    ]))
}

/// Fields to inspect in a unique pair whose valid PDUs disagree.
pub fn mismatch_fields(request: &str, response: &str) -> Option<Json> {
    if matches(request, response) {
        return None;
    }
    let request = request.strip_prefix("modbus-pdu-v2:")?;
    let response = response.strip_prefix("modbus-pdu-v2:")?;
    if let (Some(a), Some(b)) = (parts::<3>(request, "mask:"), parts::<3>(response, "mask:")) {
        return Some(Json::array(
            ["address_zero_based", "and_mask", "or_mask"]
                .into_iter()
                .zip(a)
                .zip(b)
                .filter_map(|((name, x), y)| (x != y).then_some(Json::from(name))),
        ));
    }
    if let Some((category, start)) = device_fields(request, response) {
        return Some(Json::array(
            [("read_category", category), ("first_object_id", start)]
                .into_iter()
                .filter_map(|(name, agrees)| (!agrees).then_some(Json::from(name))),
        ));
    }
    if let (Some([f, a, v]), Some([_, b, w])) =
        (parts(request, "write:"), parts(response, "write:"))
    {
        let names = if f <= 6 {
            ["address_zero_based", "wire_value"]
        } else {
            ["starting_address_zero_based", "quantity"]
        };
        return Some(Json::array(
            names
                .into_iter()
                .zip([a != b, v != w])
                .filter_map(|(name, diff)| diff.then_some(Json::from(name))),
        ));
    }
    if let (Some(a), Some(b)) = (
        request.strip_prefix("file-echo:"),
        response.strip_prefix("file-echo:"),
    ) {
        return Some(Json::array(
            [
                "file_number",
                "record_number",
                "record_words",
                "register_u16",
            ]
            .into_iter()
            .zip(a.split(':').zip(b.split(':')))
            .filter_map(|(name, (a, b))| (a != b).then_some(Json::from(name))),
        ));
    }
    let fields: &[&str] = if let (Some([f, _, count]), Some([_, n, _])) =
        (parts(request, "read:"), parts(response, "data:"))
    {
        if f <= 2 && n == count.div_ceil(8) {
            &["unused_high_bits"]
        } else {
            &["request_quantity", "response_byte_count"]
        }
    } else if request.starts_with("file:") {
        &["file_record_order_and_lengths"]
    } else if request.starts_with("id-request:") {
        &["read_category", "first_object_id"]
    } else {
        &["echoed_request_fields"]
    };
    Some(Json::array(fields.iter().copied().map(Json::from)))
}
