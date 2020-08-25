#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PacketError {
    CannotInstantiatePacket,
    InvalidPacketSignature,
    CannotParsePacket(ParserError),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PacketError::CannotInstantiatePacket => write!(f, "Can't instantiate AnnouncementPacket instance from providing data"),
            PacketError::InvalidPacketSignature => write!(f, "Announcement packet has invalid signature on packet data"),
            PacketError::CannotParsePacket(e) => write!(f, "Can't parse packet to Announcement {}", e),
        }
    }
}

impl std::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParserError {
    CannotParseHeader(&'static str),
    CannotParseAuthData(&'static str),
    CannotParseEntity(&'static str),
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParserError::CannotParseHeader(fail_reason) => write!(f, "Can't parse header: {}", fail_reason),
            ParserError::CannotParseAuthData(fail_reason) => write!(f, "Can't parse sender auth data: {}", fail_reason),
            ParserError::CannotParseEntity(fail_reason) => write!(f, "Can't parse entity: {}", fail_reason),
        }
    }
}

impl std::error::Error for ParserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}