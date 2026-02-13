//! Entropy pool — circular buffer for entropy byte storage.
//!
//! Provides a FIFO queue that buffers conditioned entropy bytes.
//! Memory is securely zeroed on drop.

use zeroize::Zeroize;

/// Default pool capacity in bytes.
pub const DEFAULT_POOL_CAPACITY: usize = 4096;

/// Minimum pool capacity in bytes.
pub const MIN_POOL_CAPACITY: usize = 64;

/// Circular buffer for entropy storage.
///
/// Uses a classic ring buffer with head/tail pointers. The buffer
/// has `capacity + 1` slots to distinguish full from empty state.
pub struct EntropyPool {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    max_size: usize, // capacity + 1
}

impl EntropyPool {
    /// Create a new entropy pool with the given capacity.
    ///
    /// Capacity will be clamped to at least `MIN_POOL_CAPACITY`.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(MIN_POOL_CAPACITY);
        let max_size = capacity + 1;
        EntropyPool {
            buf: vec![0u8; max_size],
            head: 0,
            tail: 0,
            max_size,
        }
    }

    /// Push bytes into the pool. Returns the number of bytes actually written.
    /// If the pool is full, excess bytes are silently dropped.
    pub fn push(&mut self, data: &[u8]) -> usize {
        let available = self.available_space();
        let to_write = data.len().min(available);

        if to_write == 0 {
            return 0;
        }

        // Copy in one or two segments depending on wrap-around
        let first_len = (self.max_size - self.tail).min(to_write);
        self.buf[self.tail..self.tail + first_len].copy_from_slice(&data[..first_len]);

        if to_write > first_len {
            let second_len = to_write - first_len;
            self.buf[..second_len].copy_from_slice(&data[first_len..to_write]);
        }

        self.tail = (self.tail + to_write) % self.max_size;
        to_write
    }

    /// Pop bytes from the pool. Returns the number of bytes actually read.
    /// If the pool has fewer bytes than requested, only available bytes are returned.
    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let available = self.len();
        let to_read = out.len().min(available);

        if to_read == 0 {
            return 0;
        }

        // Copy in one or two segments depending on wrap-around
        let first_len = (self.max_size - self.head).min(to_read);
        out[..first_len].copy_from_slice(&self.buf[self.head..self.head + first_len]);

        // Zero the read region
        self.buf[self.head..self.head + first_len].zeroize();

        if to_read > first_len {
            let second_len = to_read - first_len;
            out[first_len..to_read].copy_from_slice(&self.buf[..second_len]);
            self.buf[..second_len].zeroize();
        }

        self.head = (self.head + to_read) % self.max_size;
        to_read
    }

    /// Number of bytes currently stored in the pool.
    pub fn len(&self) -> usize {
        if self.tail >= self.head {
            self.tail - self.head
        } else {
            self.max_size - self.head + self.tail
        }
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Maximum number of bytes the pool can hold.
    pub fn capacity(&self) -> usize {
        self.max_size - 1
    }

    /// Available space for new bytes.
    fn available_space(&self) -> usize {
        self.capacity() - self.len()
    }
}

impl Drop for EntropyPool {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_push_pop_basic() {
        let mut pool = EntropyPool::new(256);
        assert!(pool.is_empty());
        assert_eq!(pool.capacity(), 256);

        let data = b"hello entropy world";
        let written = pool.push(data);
        assert_eq!(written, data.len());
        assert_eq!(pool.len(), data.len());

        let mut out = vec![0u8; data.len()];
        let read = pool.pop(&mut out);
        assert_eq!(read, data.len());
        assert_eq!(&out, data);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_pool_wrap_around() {
        let mut pool = EntropyPool::new(64);

        // Fill most of the pool
        let data1 = vec![0xAA; 50];
        let written = pool.push(&data1);
        assert_eq!(written, 50);

        // Pop half
        let mut out = vec![0u8; 30];
        pool.pop(&mut out);
        assert_eq!(pool.len(), 20);

        // Push more to cause wrap-around
        let data2 = vec![0xBB; 40];
        let written = pool.push(&data2);
        assert_eq!(written, 40);
        assert_eq!(pool.len(), 60);

        // Pop everything
        let mut out = vec![0u8; 60];
        let read = pool.pop(&mut out);
        assert_eq!(read, 60);
        assert_eq!(&out[..20], &[0xAA; 20]);
        assert_eq!(&out[20..60], &[0xBB; 40]);
    }

    #[test]
    fn test_pool_empty_pop() {
        let mut pool = EntropyPool::new(64);
        let mut out = vec![0u8; 10];
        let read = pool.pop(&mut out);
        assert_eq!(read, 0);
    }

    #[test]
    fn test_pool_full_push() {
        let mut pool = EntropyPool::new(64);
        let data = vec![0xFF; 100];
        let written = pool.push(&data);
        assert_eq!(written, 64); // Only capacity bytes written
        assert_eq!(pool.len(), 64);

        // Can't push more when full
        let written = pool.push(&[0x01]);
        assert_eq!(written, 0);
    }

    #[test]
    fn test_pool_zeroize_on_drop() {
        let pool = EntropyPool::new(64);
        let ptr = pool.buf.as_ptr();
        let len = pool.buf.len();
        drop(pool);
        // After drop, the Vec is deallocated. We trust zeroize works.
        // This test mainly ensures Drop doesn't panic.
        let _ = (ptr, len);
    }
}
