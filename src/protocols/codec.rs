//! Codec for wire messages using rkyv serialization.

use crate::messages::error::Error;
use rkyv::rancor::{Error as RkyvError, Strategy};
use rkyv::{Archive, Deserialize, Serialize, from_bytes, to_bytes};

use rkyv::bytecheck::CheckBytes;
use rkyv::ser::{Serializer, allocator::ArenaHandle, sharing::Share};
use rkyv::util::AlignedVec;
use rkyv::validation::{
    Validator, archive::ArchiveValidator, shared::SharedValidator,
};

type HighSerializer<'a> =
    Strategy<Serializer<AlignedVec, ArenaHandle<'a>, Share>, RkyvError>;
type HighValidator<'a> =
    Strategy<Validator<ArchiveValidator<'a>, SharedValidator>, RkyvError>;
type HighDeserializer = Strategy<rkyv::de::Pool, RkyvError>;

/// Marker trait.
pub trait WireMessage: Archive + Sized {}

impl<T> WireMessage for T where T: Archive + Sized {}

/// Encodes the message.
///
/// # Arguments
/// * `value` (`&T`) - Message to encode.
///
/// # Errors
/// * `Error::InvalidMessage` if serialization fails.
///
/// # Returns
/// * `Vec<u8>` - Encoded message bytes.
pub fn encode_wire<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: WireMessage,
    T: for<'a> Serialize<HighSerializer<'a>>,
{
    to_bytes::<RkyvError>(value)
        .map(|buffer| buffer.into_vec())
        .map_err(|_| Error::InvalidMessage)
}

/// Decodes the message.
///
/// # Arguments
/// * `bytes` (`&[u8]`) - Encoded message bytes.
///
/// # Errors
/// * `Error::InvalidMessage` if deserialization or validation fails.
///
/// # Returns
/// * `T` - Decoded message.
pub fn decode_wire<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: WireMessage,
    T::Archived: for<'l> CheckBytes<HighValidator<'l>>,
    T::Archived: Deserialize<T, HighDeserializer>,
{
    from_bytes::<T, RkyvError>(bytes).map_err(|_| Error::InvalidMessage)
}
