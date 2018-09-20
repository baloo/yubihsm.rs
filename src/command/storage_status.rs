//! Get storage status (i.e. currently free storage) from the `YubiHSM2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Storage_Status.html>

use super::{Command, Response};
use {Adapter, CommandType, Session, SessionError};

/// Get storage status (i.e. currently free storage) from the `YubiHSM2` device
pub fn storage_status<A: Adapter>(
    session: &mut Session<A>,
) -> Result<StorageStatusResponse, SessionError> {
    session.send_command(StorageStatusCommand {})
}

/// Request parameters for `command::storage_status`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct StorageStatusCommand {}

impl Command for StorageStatusCommand {
    type ResponseType = StorageStatusResponse;
}

/// Response from `command::storage_status`
#[derive(Serialize, Deserialize, Debug)]
pub struct StorageStatusResponse {
    /// Total number of storage records
    pub total_records: u16,

    /// Storage records which are currently free
    pub free_records: u16,

    /// Total number of storage pages
    pub total_pages: u16,

    /// Storage pages which are currently free
    pub free_pages: u16,

    /// Page size in bytes
    pub page_size: u16,
}

impl Response for StorageStatusResponse {
    const COMMAND_TYPE: CommandType = CommandType::StorageStatus;
}