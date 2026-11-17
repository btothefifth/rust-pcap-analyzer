//! Bounded summaries carried to the end of the correlation window. Payload
//! values remain in the original observations, including write and echo data.
use super::{
    pdu::{self, Pdu},
    Role,
};
use crate::{json::Json, sha256};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Summary {
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
    Echo([u8; 32]),
    FileLengths(Vec<u16>),
    DeviceRequest(u8, u8),
    DevicePage(u8, u8),
    Fifo,
    Exception,
}

impl Summary {
    pub(super) fn parse(bytes: &[u8], role: Role) -> Option<Self> {
        if !pdu::supported(bytes) {
            return None;
        }
        let pdu = pdu::parse(bytes, role).ok()?;
        Some(match pdu {
            Pdu::Read { start, count } | Pdu::ReadWrite { start, count, .. } => Self::Read {
                function: bytes[0],
                start,
                count,
            },
            Pdu::ReadData(data) => Self::Data {
                function: bytes[0],
                bytes: data.len() as u16,
                last: if bytes[0] <= 2 { *data.last()? } else { 0 },
            },
            Pdu::Single | Pdu::Mask => Self::Echo(sha256::digest(bytes)),
            Pdu::Multiple { .. } | Pdu::WriteAck { .. } => Self::Echo(sha256::digest(&bytes[..5])),
            Pdu::FifoRequest | Pdu::FifoData(_) => Self::Fifo,
            Pdu::Files(records) if bytes[0] == 20 => {
                Self::FileLengths(records.iter().map(|r| r.words).collect())
            }
            Pdu::Files(_) => Self::Echo(sha256::digest(bytes)),
            Pdu::DeviceRequest => Self::DeviceRequest(bytes[2], bytes[3]),
            Pdu::DevicePage(objects) => Self::DevicePage(bytes[2], objects.first()?.id),
            Pdu::Exception(_) => Self::Exception,
            Pdu::Opaque => return None,
        })
    }

    pub(super) fn agrees(&self, response: &Self) -> bool {
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
                c == category && (id == i || (*category != 4 && *i == 0))
            }
            (Self::Echo(_) | Self::FileLengths(_) | Self::Fifo, _) => self == response,
            _ => false,
        }
    }

    fn token(self) -> String {
        match self {
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
            Self::DevicePage(c, id) => format!("id-page:{c}:{id}"),
            Self::Echo(hash) => format!("echo:{}", sha256::hex(&hash)),
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
        }
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
    if let Some([category, id]) = parts(request, "id-request:") {
        let Some([c, i]) = parts(response, "id-page:") else {
            return false;
        };
        let (Ok(category), Ok(id), Ok(c), Ok(i)) = (
            category.try_into(),
            id.try_into(),
            c.try_into(),
            i.try_into(),
        ) else {
            return false;
        };
        return Summary::DeviceRequest(category, id).agrees(&Summary::DevicePage(c, i));
    }
    if request.starts_with("modbus-bits-v1:") || response.starts_with("modbus-bits-v1:") {
        return parts(request, "modbus-bits-v1:quantity:")
            .zip(parts(response, "modbus-bits-v1:response:"))
            .is_some_and(|([q], [n, last])| bits_match(q, n, last));
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
    let [function, start, count] = parts(request, "read:")?;
    if response.is_empty() || !matches(request, response) {
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
