// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::errors::OcErrorStatus;
use std::convert::TryFrom;

/// APDU Response
#[allow(unused)]
#[derive(Clone, Debug)]
pub struct Response {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl Response {
    pub fn check_ok(&self) -> Result<(), OcErrorStatus> {
        if !self.is_ok() {
            Err(OcErrorStatus::from((self.sw1, self.sw2)))
        } else {
            Ok(())
        }
    }

    pub fn data(&self) -> Result<&[u8], OcErrorStatus> {
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

    pub(crate) fn set_status(&mut self, new_status: [u8; 2]) {
        self.sw1 = new_status[0];
        self.sw2 = new_status[1];
    }

    pub fn status(&self) -> [u8; 2] {
        [self.sw1, self.sw2]
    }

    /// Is the response status "ok"? [0x90, 0x00]
    pub fn is_ok(&self) -> bool {
        self.status() == [0x90, 0x00]
    }
}

impl<'a> TryFrom<&[u8]> for Response {
    type Error = OcErrorStatus;

    fn try_from(buf: &[u8]) -> Result<Self, OcErrorStatus> {
        let n = buf.len();
        if n < 2 {
            return Err(OcErrorStatus::ResponseLength(buf.len()));
        }
        Ok(Response {
            data: buf[..n - 2].into(),
            sw1: buf[n - 2],
            sw2: buf[n - 1],
        })
    }
}

impl TryFrom<Vec<u8>> for Response {
    type Error = OcErrorStatus;

    fn try_from(mut data: Vec<u8>) -> Result<Self, OcErrorStatus> {
        let sw2 = data
            .pop()
            .ok_or_else(|| OcErrorStatus::ResponseLength(data.len()))?;
        let sw1 = data
            .pop()
            .ok_or_else(|| OcErrorStatus::ResponseLength(data.len()))?;

        Ok(Response { data, sw1, sw2 })
    }
}

#[cfg(test)]
mod tests {
    use crate::apdu::response::Response;
    use std::convert::TryFrom;

    #[test]
    fn test_two_bytes_data_response() {
        let res = Response::try_from(vec![0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(res.is_ok(), true);
        assert_eq!(res.data, vec![0x01, 0x02]);
    }

    #[test]
    fn test_no_data_response() {
        let res = Response::try_from(vec![0x90, 0x00]).unwrap();
        assert_eq!(res.is_ok(), true);
        assert_eq!(res.data, vec![]);
    }

    #[test]
    fn test_more_data_response() {
        let res = Response::try_from(vec![0xAB, 0x61, 0x02]).unwrap();
        assert_eq!(res.is_ok(), false);
        assert_eq!(res.data, vec![0xAB]);
    }
}
