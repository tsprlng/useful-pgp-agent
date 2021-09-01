// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Error, StatusByte};
use std::convert::TryFrom;

/// Response from the card to a command.
///
/// This object contains pure payload, without the status bytes.
/// Creating a `Response` object is only possible when the response from
/// the card showed an "ok" status code (if the status bytes were no ok,
/// you will receive an Error, never a Response).
#[derive(Debug)]
pub struct Response {
    data: Vec<u8>,
}

impl Response {
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

/// "Raw" APDU Response, including the status bytes.
///
/// This type is used for processing inside the openpgp-card crate
/// (raw responses with a non-ok status sometimes need to be processed,
/// e.g. when a card sends a response in "chained" format).
#[allow(unused)]
#[derive(Clone, Debug)]
pub(crate) struct RawResponse {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl TryFrom<RawResponse> for Response {
    type Error = Error;

    fn try_from(value: RawResponse) -> Result<Self, Self::Error> {
        if value.is_ok() {
            Ok(Response { data: value.data })
        } else {
            Err(Error::CardStatus(StatusByte::from(value.status())))
        }
    }
}

impl RawResponse {
    pub fn check_ok(&self) -> Result<(), StatusByte> {
        if !self.is_ok() {
            Err(StatusByte::from((self.sw1, self.sw2)))
        } else {
            Ok(())
        }
    }

    pub fn data(&self) -> Result<&[u8], StatusByte> {
        self.check_ok()?;
        Ok(&self.data)
    }

    /// access data even if the result status is an error status
    pub(crate) fn raw_data(&self) -> &[u8] {
        &self.data
    }

    pub(crate) fn raw_mut_data(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub(crate) fn set_status(&mut self, new_status: (u8, u8)) {
        self.sw1 = new_status.0;
        self.sw2 = new_status.1;
    }

    pub fn status(&self) -> (u8, u8) {
        (self.sw1, self.sw2)
    }

    /// Is the response status "ok"? (0x90, 0x00)
    pub fn is_ok(&self) -> bool {
        self.status() == (0x90, 0x00)
    }
}

impl TryFrom<Vec<u8>> for RawResponse {
    type Error = Error;

    fn try_from(mut data: Vec<u8>) -> Result<Self, Self::Error> {
        let sw2 = data
            .pop()
            .ok_or_else(|| Error::ResponseLength(data.len()))?;
        let sw1 = data
            .pop()
            .ok_or_else(|| Error::ResponseLength(data.len()))?;

        Ok(RawResponse { data, sw1, sw2 })
    }
}

#[cfg(test)]
mod tests {
    use crate::apdu::response::RawResponse;
    use std::convert::TryFrom;

    #[test]
    fn test_two_bytes_data_response() {
        let res = RawResponse::try_from(vec![0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(res.is_ok(), true);
        assert_eq!(res.data, vec![0x01, 0x02]);
    }

    #[test]
    fn test_no_data_response() {
        let res = RawResponse::try_from(vec![0x90, 0x00]).unwrap();
        assert_eq!(res.is_ok(), true);
        assert_eq!(res.data, vec![]);
    }

    #[test]
    fn test_more_data_response() {
        let res = RawResponse::try_from(vec![0xAB, 0x61, 0x02]).unwrap();
        assert_eq!(res.is_ok(), false);
        assert_eq!(res.data, vec![0xAB]);
    }
}
