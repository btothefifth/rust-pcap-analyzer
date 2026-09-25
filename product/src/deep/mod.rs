//! Independent, bounded protocol-depth observations above the capture engine.
//! These are interpretations of captured evidence, never device-effect claims.
pub mod bacnet;
pub mod ber;
pub mod bgp;
pub mod bgp_association;
pub mod bgp_import;
pub mod bgp_manager;
pub mod bgp_mrt;
pub mod bgp_mrt_store;
pub mod bgp_pipeline;
pub mod bgp_policy;
pub mod bgp_replay;
pub mod bgp_rib;
pub mod bgp_session;
pub mod bgp_state;
pub mod bgp_store;
pub mod cip;
pub mod continuation;
pub mod dnp;
pub mod dnp_file;
pub mod fieldbus;
pub mod iec104;
pub mod iec61850;
pub mod iso;
pub mod maps;
pub mod model;
pub mod opcua;
pub mod reassembly;
pub mod sink;
pub mod zigbee;

pub use model::{Context, Field, Limits, Report, Status};
use pcap_evidence::{provenance::EvidenceBytes, Result};

/// Decode one *already framed* protocol unit. Segmentation belongs to Session.
/// The caller supplies the protocol hypothesis; selection is not a port verdict.
pub fn decode(
    protocol: &str,
    bytes: &EvidenceBytes,
    context: &Context,
    limits: &Limits,
) -> Result<Report> {
    limits.validate()?;
    match protocol {
        "dnp3.objects" => dnp::objects(bytes, context.function, limits),
        "modbus.registers" => maps::raw_registers(bytes, limits),
        "bacnet_ip" => bacnet::decode(bytes, limits),
        "enip_cip" => cip::decode(bytes, limits),
        "iec104" => iec104::decode(bytes, limits),
        "iso_cotp" | "s7" => iso::tpkt(bytes, limits),
        "mms" => iso::mms(bytes, limits),
        "goose" | "sampled_values" => iec61850::decode(protocol, bytes, limits),
        "opcua_tcp" => opcua::decode(bytes, context.ua_security_none, limits),
        "ethercat" | "profinet_rt" | "powerlink" | "stp" => {
            fieldbus::decode(protocol, bytes, limits)
        }
        "zigbee" | "ieee802154" => zigbee::decode(bytes, context.fcs_present, limits),
        _ => {
            let mut r = Report::new("unknown", bytes, limits)?;
            r.note(Status::Unsupported, "no_depth_decoder", 0, bytes.len())?;
            Ok(r)
        }
    }
}
