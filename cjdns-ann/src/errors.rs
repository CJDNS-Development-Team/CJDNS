use thiserror::Error;

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum PacketError {
    #[error("Can't instantiate AnnouncementPacket from providing data")]
    CannotInstantiatePacket,

    #[error("Announcement packet has invalid signature on packet data")]
    InvalidPacketSignature,

    #[error("Can't parse packet to Announcement {0}")]
    CannotParsePacket(#[source] ParserError),
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ParserError {
    #[error("Can't parse header: {0}")]
    CannotParseHeader(&'static str),

    #[error("Can't parse sender auth data: {0}")]
    CannotParseAuthData(&'static str),

    #[error("Can't parse entity: {0}")]
    CannotParseEntity(&'static str),

    #[error("Can't parse link state: {0}")]
    CannotParseLinkState(&'static str),
}