//! Zeroizing memory allocator wrapper.
//!
//! Provides a global allocator that zeros all freed memory, preventing
//! residual secret data from persisting in the heap after deallocation.
//!
//! # Usage
//!
//! Enable with the `zeroize-alloc` feature and set as global allocator:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: hitls_crypto::zalloc::ZeroizingAllocator<std::alloc::System> =
//!     hitls_crypto::zalloc::ZeroizingAllocator(std::alloc::System);
//! ```

use core::alloc::{GlobalAlloc, Layout};

/// A wrapper allocator that zeros memory on deallocation.
///
/// Wraps any `GlobalAlloc` implementation and adds zeroization of all
/// deallocated memory blocks. This provides defense-in-depth against
/// heap memory disclosure of cryptographic secrets.
pub struct ZeroizingAllocator<A: GlobalAlloc>(pub A);

// SAFETY: ZeroizingAllocator delegates to the inner allocator for alloc,
// and additionally zeros memory before calling the inner dealloc. The
// ptr::write_bytes call is safe because the memory region [ptr, ptr+size)
// is valid and owned by us until we pass it to the inner dealloc.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroizingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegating to inner allocator with same layout
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Zero the memory before freeing to prevent residual secrets
        // SAFETY: ptr is valid for layout.size() bytes (owned by us before dealloc)
        unsafe {
            core::ptr::write_bytes(ptr, 0, layout.size());
            self.0.dealloc(ptr, layout);
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegating to inner allocator with same layout
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // If shrinking, zero the tail before realloc
        // SAFETY: ptr is valid for layout.size() bytes
        if new_size < layout.size() {
            unsafe {
                core::ptr::write_bytes(ptr.add(new_size), 0, layout.size() - new_size);
            }
        }
        // SAFETY: delegating to inner allocator
        unsafe { self.0.realloc(ptr, layout, new_size) }
    }
}
