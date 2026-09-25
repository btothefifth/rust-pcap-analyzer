use pcap_evidence::json::Json;

fn samples() -> Vec<Json> {
    vec![
        Json::Null,
        true.into(),
        false.into(),
        0u64.into(),
        u64::MAX.into(),
        "".into(),
        "quotes\" slash\\ newline\n return\r tab\t backspace\u{8} formfeed\u{c} null\0 \u{1f} café 🔎".into(),
        Json::Array(vec![]),
        Json::Object(vec![]),
        Json::object([
            ("escaped\"key", "value\n".into()),
            ("nested", Json::array([Json::Null, 15u8.into(), "λ".into()])),
        ]),
    ]
}

#[test]
fn bounded_size_and_encoding_preserve_every_json_variant() {
    for value in samples() {
        let expected = value.encode();
        assert_eq!(
            value.encoded_len_bounded(expected.len()).unwrap(),
            expected.len()
        );
        assert_eq!(value.encode_bounded(expected.len()).unwrap(), expected);
        assert!(value.encode_bounded(expected.len() - 1).is_err());
        assert!(value.encoded_len_bounded(expected.len() - 1).is_err());
    }
}

#[test]
fn line_quota_includes_the_newline_and_exact_utf8_bytes() {
    for value in samples() {
        let expected = format!("{}\n", value.encode());
        assert_eq!(value.encode_bounded_line(expected.len()).unwrap(), expected);
        assert!(value.encode_bounded_line(expected.len() - 1).is_err());
        assert!(value.encode_bounded_line(0).is_err());
    }
}

#[test]
fn rejected_append_leaves_the_existing_destination_unchanged() {
    for value in samples() {
        let prefix = "existing UTF-8 λ:";
        let mut out = prefix.to_owned();
        let total = prefix.len() + value.encode().len();
        assert!(value.append_bounded(&mut out, total - 1).is_err());
        assert_eq!(out, prefix);
        assert!(value.append_bounded(&mut out, prefix.len() - 1).is_err());
        assert_eq!(out, prefix);
        value.append_bounded(&mut out, total).unwrap();
        assert_eq!(out, format!("{prefix}{}", value.encode()));
    }
}

#[test]
fn decimal_size_boundaries_are_exact_without_temporary_strings() {
    for number in [0u64, 9, 10, 99, 100, 999, 1000, u32::MAX as u64, u64::MAX] {
        let expected = number.to_string();
        assert_eq!(
            Json::from(number).encoded_len_bounded(20).unwrap(),
            expected.len()
        );
    }
}
