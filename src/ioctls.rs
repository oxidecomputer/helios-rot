// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ffi::c_void;

use rustix::ioctl::{Ioctl, IoctlOutput, Opcode};

use crate::ffi::{
    OS_ROT_IOC_ATTEST, OS_ROT_IOC_GET_CERTS, OsRotAttest, OsRotCerts,
};

pub(crate) struct GetCerts<'a>(pub(crate) &'a mut OsRotCerts);

unsafe impl Ioctl for GetCerts<'_> {
    type Output = ();
    const IS_MUTATING: bool = true;

    fn opcode(&self) -> Opcode {
        OS_ROT_IOC_GET_CERTS
    }
    fn as_ptr(&mut self) -> *mut c_void {
        (self.0 as *mut OsRotCerts).cast()
    }
    unsafe fn output_from_ptr(
        _: IoctlOutput,
        _: *mut c_void,
    ) -> rustix::io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Attest<'a>(pub(crate) &'a mut OsRotAttest);

unsafe impl Ioctl for Attest<'_> {
    type Output = ();
    const IS_MUTATING: bool = true;

    fn opcode(&self) -> Opcode {
        OS_ROT_IOC_ATTEST
    }
    fn as_ptr(&mut self) -> *mut c_void {
        (self.0 as *mut OsRotAttest).cast()
    }
    unsafe fn output_from_ptr(
        _: IoctlOutput,
        _: *mut c_void,
    ) -> rustix::io::Result<()> {
        Ok(())
    }
}
