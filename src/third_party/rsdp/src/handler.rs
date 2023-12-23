use core::{ops::Deref, ptr::NonNull};

/// Describes a physical mapping created by `AcpiHandler::map_physical_region` and unmapped by
/// `AcpiHandler::unmap_physical_region`. The region mapped must be at least `size_of::<T>()`
/// bytes, but may be bigger.
pub struct PhysicalMapping<H, T>
where
    H: AcpiHandler,
{
    physical_start: usize,
    virtual_start: NonNull<T>,
    region_length: usize, // Can be equal or larger than size_of::<T>()
    mapped_length: usize, // Differs from `region_length` if padding is added for alignment
    handler: H,
}

impl<H, T> PhysicalMapping<H, T>
where
    H: AcpiHandler,
{
    /// Construct a new `PhysicalMapping`.
    /// `mapped_length` may differ from `region_length` if padding is added for alignment.
    ///
    /// ## Safety
    ///
    /// This function must only be called by an `AcpiHandler` of type `H` to make sure that it's safe to unmap the mapping.
    ///
    /// - `virtual_start` must be a valid pointer.
    /// - `region_length` must be equal to or larger than `size_of::<T>()`.
    /// - `handler` must be the same `AcpiHandler` that created the mapping.
    pub unsafe fn new(
        physical_start: usize,
        virtual_start: NonNull<T>,
        region_length: usize,
        mapped_length: usize,
        handler: H,
    ) -> Self {
        Self { physical_start, virtual_start, region_length, mapped_length, handler }
    }

    pub fn physical_start(&self) -> usize {
        self.physical_start
    }

    pub fn virtual_start(&self) -> NonNull<T> {
        self.virtual_start
    }

    pub fn region_length(&self) -> usize {
        self.region_length
    }

    pub fn mapped_length(&self) -> usize {
        self.mapped_length
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }
}

unsafe impl<H: AcpiHandler + Send, T: Send> Send for PhysicalMapping<H, T> {}

impl<H, T> Deref for PhysicalMapping<H, T>
where
    H: AcpiHandler,
{
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.virtual_start.as_ref() }
    }
}

impl<H, T> Drop for PhysicalMapping<H, T>
where
    H: AcpiHandler,
{
    fn drop(&mut self) {
        H::unmap_physical_region(self)
    }
}

/// An implementation of this trait must be provided to allow `acpi` to access platform-specific
/// functionality, such as mapping regions of physical memory. You are free to implement these
/// however you please, as long as they conform to the documentation of each function. The handler is stored in
/// every `PhysicalMapping` so it's able to unmap itself when dropped, so this type needs to be something you can
/// clone/move about freely (e.g. a reference, wrapper over `Rc`, marker struct, etc.).
pub trait AcpiHandler: Clone {
    /// Given a physical address and a size, map a region of physical memory that contains `T` (note: the passed
    /// size may be larger than `size_of::<T>()`). The address is not neccessarily page-aligned, so the
    /// implementation may need to map more than `size` bytes. The virtual address the region is mapped to does not
    /// matter, as long as it is accessible to `acpi`.
    ///
    /// ## Safety
    ///
    /// - `physical_address` must point to a valid `T` in physical memory.
    /// - `size` must be at least `size_of::<T>()`.
    unsafe fn map_physical_region<T>(&self, physical_address: usize, size: usize) -> PhysicalMapping<Self, T>;

    /// Unmap the given physical mapping. This is called when a `PhysicalMapping` is dropped, you should **not** manually call this.
    ///
    /// Note: A reference to the handler used to construct `region` can be acquired by calling [`PhysicalMapping::handler`].
    fn unmap_physical_region<T>(region: &PhysicalMapping<Self, T>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_send_sync() {
        // verify that PhysicalMapping implements Send and Sync
        fn test_send_sync<T: Send>() {}
        fn caller<H: AcpiHandler + Send, T: Send>() {
            test_send_sync::<PhysicalMapping<H, T>>();
        }
    }
}
