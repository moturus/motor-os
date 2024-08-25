// From https://github.com/slint-ui/pin-weak.

// use alloc::{rc::Rc, sync::Arc};
// use core::pin::Pin;

macro_rules! implementation {
    ($Rc:ident, $Weak:ident, $rc_lit:literal) => {
        pub use core::pin::Pin;
        #[derive(Debug)]
        pub struct PinWeak<T: ?Sized>(Weak<T>);
        impl<T> Default for PinWeak<T> {
            fn default() -> Self {
                Self(Weak::default())
            }
        }
        impl<T: ?Sized> Clone for PinWeak<T> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }
        impl<T: ?Sized> PinWeak<T> {
            pub fn downgrade(rc: Pin<$Rc<T>>) -> Self {
                // Safety: we will never return anything else than a Pin<Rc>
                unsafe { Self($Rc::downgrade(&Pin::into_inner_unchecked(rc))) }
            }
            pub fn upgrade(&self) -> Option<Pin<$Rc<T>>> {
                // Safety: the weak was constructed from a Pin<Rc<T>>
                self.0.upgrade().map(|rc| unsafe { Pin::new_unchecked(rc) })
            }

            /// Equivalent to [`Weak::strong_count`]
            pub fn strong_count(&self) -> usize {
                self.0.strong_count()
            }

            /// Equivalent to [`Weak::weak_count`]
            pub fn weak_count(&self) -> usize {
                self.0.weak_count()
            }

            /// Equivalent to [`Weak::ptr_eq`]
            pub fn ptr_eq(&self, other: &Self) -> bool {
                self.0.ptr_eq(&other.0)
            }
        }

        impl<T> PinWeak<T> {
            pub fn new_cyclic<F>(data_fn: F) -> Pin<$Rc<T>> where F: FnOnce(&Self) -> T {

                let rc = $Rc::new_cyclic(|weak| data_fn(&Self(weak.clone())));
                // Safety: Nobody else had access to the unpinned Rc before.
                unsafe { Pin::new_unchecked(rc) }

            }
        }
    };
}

pub mod rc {
    pub use alloc::rc::{Rc, Weak};
    implementation! {Rc, Weak, "Rc"}
}

pub mod sync {
    pub use alloc::sync::{Arc, Weak};
    implementation! {Arc, Weak, "Arc"}
}