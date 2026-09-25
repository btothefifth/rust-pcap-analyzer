#![cfg(feature = "industrial")]
use pcap_evidence_product::protocols::Protocol;
fn bacnet(apdu: &[u8]) -> Vec<u8> {
    let mut b = vec![0x81, 10, 0, 0, 1, 0];
    b.extend_from_slice(apdu);
    let n = b.len() as u16;
    b[2..4].copy_from_slice(&n.to_be_bytes());
    b
}
fn enip(path: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 32];
    b[0] = 0x6f;
    b[30] = 2;
    b.extend_from_slice(&[0, 0, 0, 0]);
    let mut cip = vec![0x0e, (path.len() / 2) as u8];
    cip.extend_from_slice(path);
    b.extend_from_slice(&[0xb2, 0]);
    b.extend_from_slice(&(cip.len() as u16).to_le_bytes());
    b.extend_from_slice(&cip);
    let n = (b.len() - 24) as u16;
    b[2..4].copy_from_slice(&n.to_le_bytes());
    b
}
#[test]
fn bacnet_who_is_bounds() {
    let b = bacnet(&[0x10, 8, 0x09, 1, 0x1a, 0x01, 0x00]);
    let d = Protocol::BacnetIp.decode(&b).unwrap();
    assert_eq!(d.support, "implemented-partial");
    assert!(d.json().encode().contains("device_instance_high"));
    assert!(Protocol::BacnetIp
        .decode(&bacnet(&[0x10, 8, 0x09, 3, 0x19, 2]))
        .is_err());
}
#[test]
fn bacnet_i_am_device_metadata() {
    let d = Protocol::BacnetIp
        .decode(&bacnet(&[
            0x10, 0, 0xc4, 0x02, 0, 0, 1, 0x22, 0x05, 0xc4, 0x91, 3, 0x22, 1, 4,
        ]))
        .unwrap();
    assert!(d.json().encode().contains("vendor_id"));
    assert!(d.json().encode().contains("object_instance"));
}
#[test]
fn read_property_has_exact_object_and_property_ranges() {
    let b = bacnet(&[0, 5, 7, 12, 0x0c, 0x02, 0, 0, 1, 0x19, 85]);
    let d = Protocol::BacnetIp.decode(&b).unwrap();
    let f = d
        .fields
        .iter()
        .find(|x| x.name == "property_identifier")
        .unwrap();
    assert_eq!(&b[f.start..f.end], &[85]);
}
#[test]
fn duplicate_read_property_field_rejected() {
    let b = bacnet(&[0, 5, 7, 12, 0x0c, 0x02, 0, 0, 1, 0x19, 85, 0x19, 85]);
    assert!(Protocol::BacnetIp.decode(&b).is_err());
}
#[test]
fn write_property_preserves_value_without_claiming_device_effect() {
    let b = bacnet(&[
        0, 5, 7, 15, 0x0c, 0x02, 0, 0, 1, 0x19, 85, 0x3e, 0x21, 42, 0x3f, 0x49, 16,
    ]);
    let d = Protocol::BacnetIp.decode(&b).unwrap();
    assert!(d.json().encode().contains("property_value_sha256"));
    assert!(d
        .issues
        .contains(&"property_value_type_and_device_effect_not_established"));
}
#[test]
fn write_priority_and_tag_pairing_are_checked() {
    for suffix in [
        vec![0x3e, 0x21, 42, 0x3f, 0x49, 17],
        vec![0x3e, 0x21, 42, 0x4f],
    ] {
        let mut a = vec![0, 5, 7, 15, 0x0c, 0x02, 0, 0, 1, 0x19, 85];
        a.extend(suffix);
        assert!(Protocol::BacnetIp.decode(&bacnet(&a)).is_err());
    }
}
#[test]
fn cip_logical_paths_preserve_order_and_duplicate_segments() {
    let b = enip(&[0x20, 1, 0x24, 2, 0x30, 3, 0x30, 4]);
    let d = Protocol::Enip.decode(&b).unwrap();
    let s = d.json().encode();
    assert_eq!(s.matches("\"kind\":\"attribute\"").count(), 2);
    assert!(s.contains("path_segments"));
}
#[test]
fn cip_wide_logical_segment_padding_checked() {
    assert!(Protocol::Enip.decode(&enip(&[0x21, 0, 1, 0])).is_ok());
    assert!(Protocol::Enip.decode(&enip(&[0x21, 1, 1, 0])).is_err());
}
#[test]
fn cip_unknown_path_is_not_guessed() {
    let d = Protocol::Enip.decode(&enip(&[0xe0, 0])).unwrap();
    assert!(d.issues.contains(&"unsupported_cip_path_segments_retained"));
}
#[test]
fn cip_ansi_symbol_length_and_padding() {
    assert!(Protocol::Enip
        .decode(&enip(&[0x91, 3, b'a', b'b', b'c', 0]))
        .is_ok());
    assert!(Protocol::Enip
        .decode(&enip(&[0x91, 3, b'a', b'b', b'c', 1]))
        .is_err());
}
#[test]
fn valid_service_neighbors_all_truncate_safely() {
    for (p, b) in [
        (Protocol::Enip, enip(&[0x20, 1, 0x24, 1, 0x30, 1])),
        (
            Protocol::BacnetIp,
            bacnet(&[0, 5, 7, 12, 0x0c, 2, 0, 0, 1, 0x19, 85]),
        ),
    ] {
        for n in 0..b.len() {
            assert!(p.decode(&b[..n]).is_err());
        }
    }
}
