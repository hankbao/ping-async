// icmp.rs - ICMP packet construction and parsing module

use core::fmt;
use std::convert::TryFrom;
use std::io;
use std::net::IpAddr;

/// ICMP message types for echo request/reply operations.
///
/// This enum defines the standard ICMP type codes used for ping operations
/// across IPv4 and IPv6 protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    /// IPv4 Echo Request (Type 8)
    EchoRequestV4 = 8,
    /// IPv4 Echo Reply (Type 0)
    EchoReplyV4 = 0,
    /// IPv6 Echo Request (Type 128)
    EchoRequestV6 = 128,
    /// IPv6 Echo Reply (Type 129)
    EchoReplyV6 = 129,
}

impl IcmpType {
    /// Get the appropriate echo request type for the given IP address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address to determine the ICMP type for
    ///
    /// # Returns
    ///
    /// Returns `EchoRequestV4` for IPv4 addresses, `EchoRequestV6` for IPv6 addresses.
    pub fn echo_request_for(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IcmpType::EchoRequestV4,
            IpAddr::V6(_) => IcmpType::EchoRequestV6,
        }
    }

    /// Get the appropriate echo reply type for the given IP address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IP address to determine the ICMP type for
    ///
    /// # Returns
    ///
    /// Returns `EchoReplyV4` for IPv4 addresses, `EchoReplyV6` for IPv6 addresses.
    pub fn echo_reply_for(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IcmpType::EchoReplyV4,
            IpAddr::V6(_) => IcmpType::EchoReplyV6,
        }
    }

    /// Convert the ICMP type to its raw u8 value.
    ///
    /// # Returns
    ///
    /// The numeric ICMP type code as defined in the RFCs.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for IcmpType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IcmpType::EchoReplyV4),
            8 => Ok(IcmpType::EchoRequestV4),
            128 => Ok(IcmpType::EchoRequestV6),
            129 => Ok(IcmpType::EchoReplyV6),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid ICMP type value",
            )),
        }
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpType::EchoRequestV4 => write!(f, "EchoRequestV4"),
            IcmpType::EchoReplyV4 => write!(f, "EchoReplyV4"),
            IcmpType::EchoRequestV6 => write!(f, "EchoRequestV6"),
            IcmpType::EchoReplyV6 => write!(f, "EchoReplyV6"),
        }
    }
}

/// ICMP packet structure for constructing and parsing ICMP echo packets.
///
/// This struct provides functionality to create ICMP echo request packets,
/// parse incoming echo reply packets, and extract packet fields. It handles
/// the platform-specific differences in packet format and checksum calculation.
///
/// # Examples
///
/// ```rust
/// use ping_async::icmp::IcmpPacket;
/// use std::net::IpAddr;
///
/// let target = "127.0.0.1".parse::<IpAddr>().unwrap();
/// let packet = IcmpPacket::new_echo_request(target, 0x1234, 1, &[1, 2, 3, 4]);
/// 
/// assert_eq!(packet.identifier(), 0x1234);
/// assert_eq!(packet.sequence(), 1);
/// assert_eq!(packet.payload(), &[1, 2, 3, 4]);
/// ```
#[derive(Clone)]
pub struct IcmpPacket {
    data: Vec<u8>, // raw packet data
}

impl IcmpPacket {
    /// Create a new ICMP echo request packet for the specified target address.
    ///
    /// This is a convenience method that automatically selects the appropriate
    /// ICMP type (IPv4 or IPv6) based on the target address.
    ///
    /// # Arguments
    ///
    /// * `target_addr` - The destination IP address
    /// * `identifier` - A 16-bit identifier to match requests with replies
    /// * `sequence` - A 16-bit sequence number for this packet
    /// * `payload` - Optional payload data to include in the packet
    ///
    /// # Returns
    ///
    /// A new `IcmpPacket` with the appropriate checksum calculated (for IPv4).
    /// IPv6 checksums are handled by the kernel.
    pub fn new_echo_request(
        target_addr: IpAddr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Self {
        let icmp_type = IcmpType::echo_request_for(target_addr);
        Self::new(icmp_type, 0, identifier, sequence, payload)
    }

    /// Create a new ICMP packet with the given parameters
    pub fn new(
        icmp_type: IcmpType,
        code: u8,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Self {
        let header_len = 8;
        let total_len = header_len + payload.len();
        let mut data = Vec::with_capacity(total_len);

        // ICMP header
        data.push(icmp_type.as_u8()); // Type
        data.push(code); // Code
        data.push(0); // Checksum (placeholder)
        data.push(0); // Checksum (placeholder)
        data.extend_from_slice(&identifier.to_be_bytes()); // Identifier
        data.extend_from_slice(&sequence.to_be_bytes()); // Sequence

        // Payload
        data.extend_from_slice(payload);

        let mut packet = IcmpPacket { data };

        // Calculate and set checksum for IPv4
        if matches!(icmp_type, IcmpType::EchoRequestV4 | IcmpType::EchoReplyV4) {
            let checksum = Self::calculate_checksum(&packet.data);
            packet.set_checksum(checksum);
        }

        packet
    }

    /// Get the packet type
    pub fn icmp_type(&self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        self.data[0]
    }

    /// Get the packet code
    pub fn code(&self) -> u8 {
        if self.data.len() < 2 {
            return 0;
        }
        self.data[1]
    }

    #[cfg(test)]
    /// Get the checksum
    pub fn checksum(&self) -> u16 {
        if self.data.len() < 4 {
            return 0;
        }
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Set the checksum
    pub fn set_checksum(&mut self, checksum: u16) {
        if self.data.len() >= 4 {
            let bytes = checksum.to_be_bytes();
            self.data[2] = bytes[0];
            self.data[3] = bytes[1];
        }
    }

    /// Get the identifier
    pub fn identifier(&self) -> u16 {
        if self.data.len() < 6 {
            return 0;
        }
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Get the sequence number
    pub fn sequence(&self) -> u16 {
        if self.data.len() < 8 {
            return 0;
        }
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    /// Get the payload
    pub fn payload(&self) -> &[u8] {
        if self.data.len() <= 8 {
            return &[];
        }
        &self.data[8..]
    }

    /// Get the raw packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    #[cfg(test)]
    /// Verify the checksum (for IPv4 packets)
    fn verify_checksum(&self) -> bool {
        let icmp_type = self.icmp_type();

        // IPv6 checksums are handled by the kernel
        if icmp_type != IcmpType::EchoRequestV4.as_u8()
            || icmp_type != IcmpType::EchoReplyV4.as_u8()
        {
            return true;
        }

        // For verification, calculate checksum including the existing checksum field
        let mut sum = 0u32;
        let mut i = 0;

        // Sum all 16-bit words including the checksum field
        while i < self.data.len() {
            let word = if i + 1 < self.data.len() {
                u16::from_be_bytes([self.data[i], self.data[i + 1]])
            } else {
                u16::from_be_bytes([self.data[i], 0])
            };
            sum += word as u32;
            i += 2;
        }

        // Add carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // For a valid packet, the sum should be 0xFFFF (all ones)
        sum as u16 == 0xFFFF
    }

    /// Parse an ICMP packet from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes including the ICMP header
    ///
    /// # Returns
    ///
    /// Returns `Some(IcmpPacket)` if the data contains a valid ICMP header,
    /// `None` if the data is too short (less than 8 bytes).
    pub fn parse(data: &[u8]) -> Option<IcmpPacket> {
        if data.len() < 8 {
            return None; // Minimum ICMP header size
        }

        Some(IcmpPacket {
            data: data.to_vec(),
        })
    }

    /// Parse an ICMP reply from raw socket data, handling platform-specific offsets.
    ///
    /// This method handles the platform differences in how ICMP packets are received:
    /// - On macOS, IPv4 ICMP packets include the IP header which must be skipped
    /// - On Linux, ICMP packets start immediately with the ICMP header
    /// - IPv6 packets don't include IP headers on either platform
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data as received from the socket
    /// * `target_addr` - The target address to determine expected reply type
    ///
    /// # Returns
    ///
    /// Returns `Some(IcmpPacket)` if the data contains a valid echo reply for
    /// the target address, `None` otherwise.
    pub fn parse_reply(data: &[u8], target_addr: IpAddr) -> Option<IcmpPacket> {
        let icmp_offset = if cfg!(target_os = "macos") && target_addr.is_ipv4() {
            20 // Skip IP header for IPv4 on macOS
        } else {
            0
        };

        if data.len() < icmp_offset + 8 {
            return None; // Not enough data
        }

        let icmp_data = &data[icmp_offset..];

        // Check if this is an echo reply
        let expected_reply_type = IcmpType::echo_reply_for(target_addr);
        if icmp_data[0] != expected_reply_type.as_u8() {
            return None; // Not an echo reply
        }

        Self::parse(icmp_data)
    }

    /// Calculate Internet checksum (RFC 1071)
    /// Returns the 16-bit one's complement checksum
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;

        // Sum 16-bit words, skipping checksum field (bytes 2-3)
        while i < data.len() {
            if i == 2 {
                i += 2; // Skip checksum field
                continue;
            }

            let word = if i + 1 < data.len() {
                u16::from_be_bytes([data[i], data[i + 1]])
            } else {
                // Odd number of bytes, pad with zero
                u16::from_be_bytes([data[i], 0])
            };

            sum += word as u32;
            i += 2;
        }

        // Add carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // One's complement
        !sum as u16
    }
}

impl fmt::Debug for IcmpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match IcmpType::try_from(self.icmp_type()).ok() {
            Some(IcmpType::EchoRequestV4) | Some(IcmpType::EchoReplyV4) => f
                .debug_struct("IcmpPacket")
                .field("icmp_type", &self.icmp_type())
                .field("code", &self.code())
                .field("identifier", &self.identifier())
                .field("sequence", &self.sequence())
                .field("payload", &self.payload())
                .finish(),
            Some(IcmpType::EchoRequestV6) | Some(IcmpType::EchoReplyV6) => f
                .debug_struct("IcmpPacket")
                .field("icmp_type", &self.icmp_type())
                .field("code", &self.code())
                .finish(),
            None => f
                .debug_struct("IcmpPacket")
                .field("icmp_type", &self.icmp_type())
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_icmp_type_conversions() {
        assert_eq!(IcmpType::EchoRequestV4.as_u8(), 8);
        assert_eq!(IcmpType::EchoReplyV4.as_u8(), 0);
        assert_eq!(IcmpType::EchoRequestV6.as_u8(), 128);
        assert_eq!(IcmpType::EchoReplyV6.as_u8(), 129);

        assert_eq!(IcmpType::try_from(8).unwrap(), IcmpType::EchoRequestV4);
        assert_eq!(IcmpType::try_from(0).unwrap(), IcmpType::EchoReplyV4);
        assert_eq!(IcmpType::try_from(128).unwrap(), IcmpType::EchoRequestV6);
        assert_eq!(IcmpType::try_from(129).unwrap(), IcmpType::EchoReplyV6);

        // Test invalid values return errors
        assert!(IcmpType::try_from(1).is_err());
        assert!(IcmpType::try_from(255).is_err());
        assert!(IcmpType::try_from(100).is_err());

        let error = IcmpType::try_from(42).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "Invalid ICMP type value");
    }

    #[test]
    fn test_icmp_type_for_addresses() {
        let ipv4_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ipv6_addr = IpAddr::V6("::1".parse().unwrap());

        assert_eq!(
            IcmpType::echo_request_for(ipv4_addr),
            IcmpType::EchoRequestV4
        );
        assert_eq!(
            IcmpType::echo_request_for(ipv6_addr),
            IcmpType::EchoRequestV6
        );
        assert_eq!(IcmpType::echo_reply_for(ipv4_addr), IcmpType::EchoReplyV4);
        assert_eq!(IcmpType::echo_reply_for(ipv6_addr), IcmpType::EchoReplyV6);
    }

    #[test]
    fn test_icmp_packet_creation() {
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];

        let packet = IcmpPacket::new_echo_request(target, 0x1234, 0x5678, &payload);

        assert_eq!(packet.icmp_type(), IcmpType::EchoRequestV4.as_u8());
        assert_eq!(packet.code(), 0);
        assert_eq!(packet.identifier(), 0x1234);
        assert_eq!(packet.sequence(), 0x5678);
        assert_eq!(packet.payload(), &payload);
        assert_eq!(packet.data.len(), 8 + payload.len());
    }

    #[test]
    fn test_icmp_packet_parsing() {
        // Create a known packet
        let original_payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let packet = IcmpPacket::new_echo_request(target, 0x1111, 0x2222, &original_payload);

        // Parse it back
        let parsed = IcmpPacket::parse(&packet.data).unwrap();

        assert_eq!(parsed.icmp_type(), IcmpType::EchoRequestV4.as_u8());
        assert_eq!(parsed.identifier(), 0x1111);
        assert_eq!(parsed.sequence(), 0x2222);
        assert_eq!(parsed.payload(), &original_payload);
    }

    #[test]
    fn test_checksum_calculation() {
        // Test with a known ICMP packet
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let payload = [0; 8]; // 8 zero bytes
        let packet = IcmpPacket::new_echo_request(target, 0x0001, 0x0001, &payload);

        // Verify checksum is calculated
        assert_ne!(packet.checksum(), 0);

        // Verify checksum validation
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_ipv6_packet_no_checksum() {
        let target = IpAddr::V6("::1".parse().unwrap());
        let payload = [1, 2, 3, 4];
        let packet = IcmpPacket::new_echo_request(target, 0x1234, 0x5678, &payload);

        // IPv6 packets should have checksum 0 (handled by kernel)
        assert_eq!(packet.checksum(), 0);
        // But verify_checksum should still return true
        assert!(packet.verify_checksum());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_parse_icmp_reply_macos() {
        let ip_header = [0u8; 20]; // 20-byte IP header on macOS
        let icmp_data = [
            0, // Echo Reply
            0, // Code
            0, 0, // Checksum
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence
            0xAA, 0xBB, 0xCC, 0xDD, // Payload
        ];

        let mut full_packet = Vec::new();
        full_packet.extend_from_slice(&ip_header);
        full_packet.extend_from_slice(&icmp_data);

        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let parsed = IcmpPacket::parse_reply(&full_packet, target).unwrap();

        assert_eq!(parsed.icmp_type(), IcmpType::EchoReplyV4.as_u8());
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x5678);
        assert_eq!(parsed.payload(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_icmp_reply_linux() {
        let icmp_data = [
            0, // Echo Reply
            0, // Code
            0, 0, // Checksum
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence
            0xAA, 0xBB, 0xCC, 0xDD, // Payload
        ];

        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let parsed = IcmpPacket::parse_reply(&icmp_data, target).unwrap();

        assert_eq!(parsed.icmp_type(), IcmpType::EchoReplyV4.as_u8());
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x5678);
        assert_eq!(parsed.payload(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_parse_icmp6_reply() {
        let icmp6_data = [
            129, // ICMPv6 Echo Reply
            0,   // Code
            0, 0, // Checksum (handled by kernel for IPv6)
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence
            0xAA, 0xBB, 0xCC, 0xDD, // Payload
        ];

        let target = IpAddr::V6("::1".parse().unwrap());
        let parsed = IcmpPacket::parse_reply(&icmp6_data, target).unwrap();

        assert_eq!(parsed.icmp_type(), IcmpType::EchoReplyV6.as_u8());
        assert_eq!(parsed.code(), 0);
        assert_eq!(parsed.identifier(), 0x1234);
        assert_eq!(parsed.sequence(), 0x5678);
        assert_eq!(parsed.payload(), &[0xAA, 0xBB, 0xCC, 0xDD]);

        // IPv6 packets don't use offset (no IP header stripping needed)
        assert_eq!(parsed.checksum(), 0); // Checksum handled by kernel
    }

    #[test]
    fn test_invalid_packets() {
        // Too short
        assert!(IcmpPacket::parse(&[1, 2, 3]).is_none());

        // Wrong type in reply parsing
        let wrong_type_packet = [
            8, // Echo Request (not Reply)
            0, // Code
            0, 0, // Checksum
            0, 0, // Identifier
            0, 0, // Sequence
        ];
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(IcmpPacket::parse_reply(&wrong_type_packet, target).is_none());
    }
}
