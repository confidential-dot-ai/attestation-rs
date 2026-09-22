//! PC Client event types (TCG PC Client Platform Firmware Profile v1.06 r52,
//! section 10.4.1, Table 27) and the EV_NO_ACTION structures replay depends on.

/// Informative events that are never extended.
pub const EV_NO_ACTION: u32 = 0x0000_0003;
/// Tagged events (`TCG_PCClientTaggedEvent`); AAEL records use this type.
pub const EV_EVENT_TAG: u32 = 0x0000_0006;

/// Table 27. A code outside it is reserved for application and OS use.
const EVENT_TYPES: [(u32, &str); 40] = [
    (0x0000_0000, "EV_PREBOOT_CERT"),
    (0x0000_0001, "EV_POST_CODE"),
    (0x0000_0002, "EV_UNUSED"),
    (0x0000_0003, "EV_NO_ACTION"),
    (0x0000_0004, "EV_SEPARATOR"),
    (0x0000_0005, "EV_ACTION"),
    (0x0000_0006, "EV_EVENT_TAG"),
    (0x0000_0007, "EV_S_CRTM_CONTENTS"),
    (0x0000_0008, "EV_S_CRTM_VERSION"),
    (0x0000_0009, "EV_CPU_MICROCODE"),
    (0x0000_000A, "EV_PLATFORM_CONFIG_FLAGS"),
    (0x0000_000B, "EV_TABLE_OF_DEVICES"),
    (0x0000_000C, "EV_COMPACT_HASH"),
    (0x0000_000D, "EV_IPL"),
    (0x0000_000E, "EV_IPL_PARTITION_DATA"),
    (0x0000_000F, "EV_NONHOST_CODE"),
    (0x0000_0010, "EV_NONHOST_CONFIG"),
    (0x0000_0011, "EV_NONHOST_INFO"),
    (0x0000_0012, "EV_OMIT_BOOT_DEVICE_EVENTS"),
    (0x0000_0013, "EV_POST_CODE2"),
    (0x8000_0000, "EV_EFI_EVENT_BASE"),
    (0x8000_0001, "EV_EFI_VARIABLE_DRIVER_CONFIG"),
    (0x8000_0002, "EV_EFI_VARIABLE_BOOT"),
    (0x8000_0003, "EV_EFI_BOOT_SERVICES_APPLICATION"),
    (0x8000_0004, "EV_EFI_BOOT_SERVICES_DRIVER"),
    (0x8000_0005, "EV_EFI_RUNTIME_SERVICES_DRIVER"),
    (0x8000_0006, "EV_EFI_GPT_EVENT"),
    (0x8000_0007, "EV_EFI_ACTION"),
    (0x8000_0008, "EV_EFI_PLATFORM_FIRMWARE_BLOB"),
    (0x8000_0009, "EV_EFI_HANDOFF_TABLES"),
    (0x8000_000A, "EV_EFI_PLATFORM_FIRMWARE_BLOB2"),
    (0x8000_000B, "EV_EFI_HANDOFF_TABLES2"),
    (0x8000_000C, "EV_EFI_VARIABLE_BOOT2"),
    (0x8000_000D, "EV_EFI_GPT_EVENT2"),
    (0x8000_0010, "EV_EFI_HCRTM_EVENT"),
    (0x8000_00E0, "EV_EFI_VARIABLE_AUTHORITY"),
    (0x8000_00E1, "EV_EFI_SPDM_FIRMWARE_BLOB"),
    (0x8000_00E2, "EV_EFI_SPDM_FIRMWARE_CONFIG"),
    (0x8000_00E3, "EV_EFI_SPDM_DEVICE_POLICY"),
    (0x8000_00E4, "EV_EFI_SPDM_DEVICE_AUTHORITY"),
];

/// The Table 27 label of an event type code.
pub fn event_type_name(code: u32) -> Option<&'static str> {
    EVENT_TYPES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|&(_, n)| n)
}

/// The event type code of a Table 27 label.
pub fn event_type_code(name: &str) -> Option<u32> {
    EVENT_TYPES
        .iter()
        .find(|(_, n)| *n == name)
        .map(|&(c, _)| c)
}

const STARTUP_LOCALITY_SIGNATURE: &[u8; 16] = b"StartupLocality\0";

/// The locality of a `TCG_EfiStartupLocalityEvent` (PFP 10.4.5.3), if
/// `event_data` is one. `Err` for a well-formed signature with a reserved
/// locality or the wrong length.
pub(crate) fn startup_locality(event_data: &[u8]) -> Option<Result<u8, String>> {
    let rest = event_data.strip_prefix(STARTUP_LOCALITY_SIGNATURE.as_slice())?;
    Some(match rest {
        [l @ (0 | 3 | 4)] => Ok(*l),
        [l] => Err(format!("startup locality {l} is reserved")),
        _ => Err(format!(
            "startup locality event is {} bytes, not 17",
            event_data.len()
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_one_to_one() {
        let all = EVENT_TYPES;
        for (i, (c, n)) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|(c2, n2)| c2 != c && n2 != n));
            assert_eq!(event_type_name(*c), Some(*n));
            assert_eq!(event_type_code(n), Some(*c));
        }
        assert_eq!(event_type_name(EV_NO_ACTION), Some("EV_NO_ACTION"));
        assert_eq!(event_type_name(0x0800_0001), None);
    }

    #[test]
    fn startup_locality_events() {
        let mut ev = b"StartupLocality\0".to_vec();
        ev.push(3);
        assert_eq!(startup_locality(&ev), Some(Ok(3)));
        ev[16] = 2;
        assert!(matches!(startup_locality(&ev), Some(Err(_))));
        ev.push(0);
        assert!(matches!(startup_locality(&ev), Some(Err(_))));
        assert_eq!(startup_locality(b"Spec ID Event03\0"), None);
    }
}
