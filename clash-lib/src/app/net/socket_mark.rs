use serde::{Deserialize, Serialize};
use std::{fmt, io};

/// A routing mark supplied by the profile. An absent mark is represented by
/// `Option<SocketMark>`, since explicitly setting zero clears SO_MARK on Linux.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SocketMark(u32);

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
        // AOSP reserves Fwmark bits 29 and 30 for the vendor.
        const VENDOR_MASK: u32 = 0x6000_0000;
        if self.0 & !VENDOR_MASK != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android socket marks may only use deployment-assigned vendor bits \
                 (mask 0x60000000)",
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

    #[test]
    fn optional_marks_keep_their_numeric_representation() {
        for mark in [0, 0x2000_0000, u32::MAX] {
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
