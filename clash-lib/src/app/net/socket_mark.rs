use serde::{Deserialize, Serialize};
use std::{fmt, io};

/// A routing mark supplied by the profile. An absent mark is represented by
/// `Option<SocketMark>`, since explicitly setting zero clears SO_MARK on Linux.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SocketMark(u32);

impl<'de> Deserialize<'de> for SocketMark {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let mark = Self(u32::deserialize(deserializer)?);
        #[cfg(all(target_os = "android", socket_mark))]
        mark.validate().map_err(serde::de::Error::custom)?;
        Ok(mark)
    }
}

impl From<u32> for SocketMark {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Display for SocketMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl SocketMark {
    #[cfg(all(target_os = "android", socket_mark))]
    pub(crate) fn validate(self) -> io::Result<()> {
        // AOSP reserves bits 21–28 for future use and bits 29–30 for vendors.
        // Keep netd's cleartext policy bits (24–25) intact if copied to
        // connmark.
        const ALLOWED_MASK: u32 = 0x7ce0_0000;
        if self.0 & !ALLOWED_MASK != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid Android routing-mark {0} ({0:#010x}): only bits 21–23 \
                     and 26–30 are allowed (mask {ALLOWED_MASK:#010x})",
                    self.0
                ),
            ));
        }
        Ok(())
    }

    #[cfg(socket_mark)]
    pub(crate) fn apply_to(self, socket: &socket2::Socket) -> io::Result<()> {
        #[cfg(target_os = "android")]
        {
            self.validate()?;
            if self.0 == 0 {
                return Ok(());
            }
            // Keep the network and permissions selected by netd.
            socket.set_mark(socket.mark()? | self.0)
        }
        #[cfg(target_os = "linux")]
        socket.set_mark(self.0)
    }

    #[cfg(not(socket_mark))]
    pub(crate) fn apply_to(self, _socket: &socket2::Socket) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SocketMark;

    #[cfg(all(target_os = "android", socket_mark))]
    #[test]
    fn invalid_mark_reports_value_and_allowed_mask() {
        let err = SocketMark::from(0x2000_0100).validate().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let message = err.to_string();
        assert!(message.contains("0x20000100"));
        assert!(message.contains("0x7ce00000"));
    }

    #[test]
    fn optional_marks_keep_their_numeric_representation() {
        for mark in [
            0,
            0x2000_0000,
            0x4000_0000,
            0x6000_0000,
            #[cfg(not(all(target_os = "android", socket_mark)))]
            u32::MAX,
        ] {
            let value = Some(SocketMark::from(mark));
            let encoded = serde_json::to_string(&value).unwrap();
            assert_eq!(encoded, mark.to_string());
            assert_eq!(
                serde_json::from_str::<Option<SocketMark>>(&encoded).unwrap(),
                value
            );
        }
        assert_eq!(
            serde_json::from_str::<Option<SocketMark>>("null").unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires permission to set SO_MARK"]
    fn linux_replaces_and_clears_the_socket_mark() -> std::io::Result<()> {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        for value in [1, 0x2000_0000, 0] {
            SocketMark::from(value).apply_to(&socket)?;
            assert_eq!(socket.mark()?, value);
        }
        Ok(())
    }

    #[cfg(not(socket_mark))]
    #[test]
    fn unsupported_platform_ignores_configured_mark() -> std::io::Result<()> {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        SocketMark::from(u32::MAX).apply_to(&socket)
    }
}
