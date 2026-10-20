pub mod attest;
pub mod health;
pub mod platform;
pub mod token;
pub mod verify;

/// Keep hardware discovery within the service's platform surface even when
/// workspace feature unification enables dstack in the library.
#[cfg(target_os = "linux")]
fn detect_platform() -> Result<attestation::PlatformType, crate::error::ApiError> {
    static DETECTED: std::sync::OnceLock<Option<attestation::PlatformType>> =
        std::sync::OnceLock::new();
    DETECTED
        .get_or_init(|| {
            let platform = attestation::detect().ok()?;
            supported_detection(platform, || {
                attestation::platforms::tdx::attest::is_available()
            })
        })
        .ok_or(crate::error::ApiError::NoPlatform)
}

#[cfg(any(target_os = "linux", test))]
fn supported_detection(
    platform: attestation::PlatformType,
    tdx_available: impl FnOnce() -> bool,
) -> Option<attestation::PlatformType> {
    if crate::config::normalize_platform(&platform.to_string()).is_some() {
        Some(platform)
    } else if platform.to_string() == "dstack" && tdx_available() {
        Some(attestation::PlatformType::Tdx)
    } else {
        None
    }
}

#[cfg(test)]
mod detection_tests {
    #[test]
    fn supported_platforms_are_not_reprobed() {
        assert_eq!(
            super::supported_detection(attestation::PlatformType::Tdx, || panic!("must not probe")),
            Some(attestation::PlatformType::Tdx)
        );
        let dstack = attestation::PlatformType::Dstack;
        assert_eq!(
            super::supported_detection(dstack, || true),
            Some(attestation::PlatformType::Tdx)
        );
        assert_eq!(super::supported_detection(dstack, || false), None);
    }
}
