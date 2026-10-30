//! Linux-only stdout pipe fast path based on `vmsplice(2)`.
//!
//! The two page-aligned staging buffers are kept alive while the kernel may
//! still reference them. Each full buffer is exactly the pipe's capacity; the
//! blocking `vmsplice` of the next full buffer therefore cannot complete until
//! the previous full buffer has drained. The final buffer is intentionally
//! retained until process exit because stdout has no portable completion signal
//! for when its reader has consumed the last bytes.

use std::alloc::{alloc, dealloc, Layout};
use std::io;
use std::os::raw::{c_int, c_uint, c_void};
use std::ptr::NonNull;

const F_SETPIPE_SZ: c_int = 1031;
const F_GETPIPE_SZ: c_int = 1032;
const TARGET_PIPE_CAPACITY: usize = 128 * 1024;
const MAX_PIPE_CAPACITY: usize = 1024 * 1024;

#[repr(C)]
struct IoVec {
    base: *const c_void,
    len: usize,
}

unsafe extern "C" {
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn getpagesize() -> c_int;
    fn vmsplice(fd: c_int, iov: *const IoVec, nr_segs: usize, flags: c_uint) -> isize;
}

struct AlignedBuffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl AlignedBuffer {
    fn new(len: usize, align: usize) -> io::Result<Self> {
        let layout = Layout::from_size_align(len, align).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid pipe buffer layout")
        })?;
        // SAFETY: `layout` is non-zero and valid, and the allocation is owned
        // by this value until its Drop implementation (or intentional leak).
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "pipe buffer allocation failed")
        })?;
        Ok(Self { ptr, layout })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the allocation is valid for `layout.size()` bytes and this
        // method has exclusive access to the buffer.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: this is the original pointer and layout returned by alloc.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

pub(crate) struct VmspliceWriter {
    fd: c_int,
    capacity: usize,
    buffers: Option<[AlignedBuffer; 2]>,
    index: usize,
    filled: usize,
    has_spliced: bool,
    finished: bool,
}

impl VmspliceWriter {
    /// Returns `None` when the descriptor is not a Linux pipe or its size is
    /// outside the range supported by this bounded fast path.
    pub(crate) fn for_fd(fd: c_int) -> io::Result<Option<Self>> {
        // SAFETY: F_GETPIPE_SZ takes no third argument and does not retain fd.
        let current_capacity = unsafe { fcntl(fd, F_GETPIPE_SZ) };
        if current_capacity <= 0 {
            return Ok(None);
        }
        let current_capacity = current_capacity as usize;
        let capacity = if current_capacity < TARGET_PIPE_CAPACITY {
            // Best effort: unprivileged callers can usually grow their pipe up
            // to the system limit. If the request is denied, keep using the
            // capacity already available rather than disabling the fast path.
            // SAFETY: F_SETPIPE_SZ takes the requested size as its third arg.
            let requested = unsafe { fcntl(fd, F_SETPIPE_SZ, TARGET_PIPE_CAPACITY as c_int) };
            if requested > 0 {
                requested as usize
            } else {
                current_capacity
            }
        } else {
            current_capacity
        };
        // SAFETY: getpagesize has no preconditions and returns the host page size.
        let page_size = unsafe { getpagesize() };
        if page_size <= 0
            || capacity > MAX_PIPE_CAPACITY
            || !capacity.is_multiple_of(page_size as usize)
        {
            return Ok(None);
        }
        let buffers = [
            AlignedBuffer::new(capacity, page_size as usize)?,
            AlignedBuffer::new(capacity, page_size as usize)?,
        ];
        Ok(Some(Self {
            fd,
            capacity,
            buffers: Some(buffers),
            index: 0,
            filled: 0,
            has_spliced: false,
            finished: false,
        }))
    }

    pub(crate) fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vmsplice output already finalized",
            ));
        }
        while !data.is_empty() {
            let n = (self.capacity - self.filled).min(data.len());
            let buffers = self.buffers.as_mut().expect("buffers live until drop");
            buffers[self.index].as_mut_slice()[self.filled..self.filled + n]
                .copy_from_slice(&data[..n]);
            self.filled += n;
            data = &data[n..];
            if self.filled == self.capacity {
                self.send_filled()?;
            }
        }
        Ok(())
    }

    /// Finalize the stream. Call only once no more bytes will be written.
    pub(crate) fn flush(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        if self.filled != 0 {
            self.send_filled()?;
        }
        self.finished = true;
        Ok(())
    }

    fn send_filled(&mut self) -> io::Result<()> {
        let len = self.filled;
        let base = self.buffers.as_ref().expect("buffers live until drop")[self.index].as_ptr();
        // SAFETY: the selected buffer is allocated and initialized through
        // `len`; it remains allocated for as long as the pipe may reference it.
        unsafe { self.send_memory(base, len)? };
        self.filled = 0;
        self.index ^= 1;
        Ok(())
    }

    /// Splice bytes from memory into the configured pipe.
    ///
    /// # Safety
    /// `base..base+len` must be readable, stable memory for the duration of the
    /// calls, and its pages must not be freed or mutated while the pipe may
    /// still reference them.
    unsafe fn send_memory(&mut self, base: *const u8, len: usize) -> io::Result<()> {
        let mut offset = 0;
        while offset < len {
            // SAFETY: upheld by this function's caller for the entire range.
            let current = unsafe { base.add(offset) };
            let iov = IoVec {
                base: current.cast(),
                len: len - offset,
            };
            // SAFETY: `iov` describes the readable region above. vmsplice does
            // not retain the iovec itself; the referenced pages remain stable
            // under the caller's safety contract.
            let written = unsafe { vmsplice(self.fd, &iov, 1, 0) };
            if written < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vmsplice returned zero",
                ));
            }
            self.has_spliced = true;
            offset += written as usize;
        }
        Ok(())
    }
}

impl Drop for VmspliceWriter {
    fn drop(&mut self) {
        if let Some(buffers) = self.buffers.take() {
            if self.has_spliced {
                // Keep the pages allocated until process exit; freeing or
                // reusing them before the pipe reader consumes its last bytes
                // would violate vmsplice's buffer-lifetime requirement.
                std::mem::forget(buffers);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{VmspliceWriter, F_GETPIPE_SZ};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::raw::c_int;
    use std::thread;

    unsafe extern "C" {
        fn pipe(fds: *mut c_int) -> c_int;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }

    #[test]
    fn vmsplice_pipe_preserves_bytes_across_full_and_partial_buffers() {
        let mut fds = [0; 2];
        // SAFETY: `fds` points to two writable integers as required by pipe(2).
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe returned fresh, uniquely owned descriptors.
        let reader = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: pipe returned a fresh, uniquely owned descriptor.
        let writer = unsafe { File::from_raw_fd(fds[1]) };
        // SAFETY: F_GETPIPE_SZ takes no third argument.
        let initial_capacity = unsafe { fcntl(writer.as_raw_fd(), F_GETPIPE_SZ) } as usize;
        let mut fast = VmspliceWriter::for_fd(writer.as_raw_fd())
            .unwrap()
            .expect("anonymous pipe should enable vmsplice");
        // Read after construction because the fast path may have raised a
        // smaller pipe to 128 KiB.
        let capacity = unsafe { fcntl(writer.as_raw_fd(), F_GETPIPE_SZ) } as usize;
        assert!(capacity >= initial_capacity);
        assert_eq!(capacity, fast.capacity);

        let payload: Vec<u8> = (0..capacity * 3 + 137)
            .map(|i| (i.wrapping_mul(37) & 0xff) as u8)
            .collect();
        let expected = payload.clone();
        let reader_thread = thread::spawn(move || {
            let mut reader = reader;
            let mut got = Vec::new();
            reader.read_to_end(&mut got).unwrap();
            got
        });
        let mut at = 0;
        for size in [19, capacity / 2, capacity + 23, capacity * 2] {
            if at == payload.len() {
                break;
            }
            let end = (at + size).min(payload.len());
            fast.write_all(&payload[at..end]).unwrap();
            at = end;
        }
        if at < payload.len() {
            fast.write_all(&payload[at..]).unwrap();
        }
        fast.flush().unwrap();
        drop(fast);
        drop(writer);

        assert_eq!(reader_thread.join().unwrap(), expected);
    }

    #[test]
    fn non_pipe_descriptor_uses_fallback() {
        let file = File::open("/dev/null").unwrap();
        assert!(VmspliceWriter::for_fd(file.as_raw_fd()).unwrap().is_none());
    }
}
