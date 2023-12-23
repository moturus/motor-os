# Design rationale

> I always hear that intrusive collections can't be done in Rust (either "can't be done safely" or "can't be done as performantly as C++"). Can you elaborate on this?

I would say that it is a combination of both "can't be done safely" and "can't be done as performantly as C++". You should keep in mind that C++ libraries such as [Boost.Intrusive](http://www.boost.org/doc/libs/release/doc/html/intrusive.html) don't exactly have a safe API and instead place a bunch of [requirements on the user](http://www.boost.org/doc/libs/1_53_0/doc/html/intrusive/usage.html#intrusive.usage.usage_lifetime) regarding object lifetimes.

There are several factor that a Rust implementation of intrusive collections must take into account:

1. Elements in a collection can't have a pointer back to the collection itself since these would become invalid if the collection is moved. C++ doesn't suffer from this limitation because it can adjust these pointers in the move constructor.

   (Not that I'm complaining about Rust's lack of move constructors. Having to deal with move constructors introduces *a lot* of complexity for collection code due to exception safety issues.)

    This basically means that we have to use NULL-terminated linked lists instead of circular linked lists. It's very slightly slower (depending on who you ask), but generally not a big deal. This same restriction also applies to normal collection types in Rust.

2. Rust doesn't have any equivalent to C++'s "pointer to member" type to tell a collection type which struct field to use for the intrusive `Link` (basically the prev/next pointers in a linked list). Instead, we use an unsafe `Adapter` trait which describes how to convert between a `*const T` and `*const Link`.

   The `intrusive_adapter!` macro provides a safe and easy way of creating and adapter type. It uses `offset_of!` and `container_of!` internally in a way that is guaranteed to be safe. This macro only supports the case where the link is a direct field of the object type; more complicated scenarios (such as nested fields) require a manual implementation of `Adapter`.

3. You can't safely give out `&mut` references to elements in a collection due to the aliasing rules (an object may be part of multiple intrusive collections at once) and because it allows the user to "break" the links in a collection with code like `mem::replace(&mut obj.link, Link::new())`.

   Since we can only give out `&` references to collection elements, any mutability must be done through `Cell` / `RefCell` / `UnsafeCell`.

4. Objects must not be moved or destroyed while they are still linked into an intrusive collection. While this basically sounds like having the collection take a shared borrow of an object when inserting it, lifetimes aren't ideal for this since they effectively restrict the lifetime of the collection to a single function.

   The basic approach that `intrusive-collections` takes is that a collection *takes ownership* of an object, usually in the form of an owned pointer (`Box<T>`, `Rc<T>`, etc), and then returns the owned pointer back to the user when the object is removed from the collection. The owned pointer type is a generic parameter of the collection (through the `Adapter` trait).

   The case of `Box<T>` is the simplest, since the collection becomes the sole owner of the object. `Rc<T>` is more interesting since the ownership is shared. This enables inserting an object into multiple intrusive collections (with multiple `Link`s in the object) without needing to worry about the object moving or dropping while still in use.

   `intrusive-collection` also supports using `&'a T` as the owned pointer type. This allows shared ownership (you can keep accessing variables that have been inserted in the collection) without the need for reference counting. Safety is ensure by restricting the lifetime of the collection such that it does not outlive any objects that have been inserted into it. As a bonus, this also works with [arenas](https://crates.io/crates/typed-arena) which give out `&'a T` references to allocated objects.

   Finally, if you really need to avoid the overhead of `Rc`, the crate also provides an `UnsafeRef` type which acts like an `Rc` but without the reference count: you are expected to free the object yourself once you are sure it is no longer in use.

So basically, `intrusive-collections` is almost as performant as C++ intrusive collections. If you want every last bit of performance, you can use `UnsafeRef` instead of `Rc` for the owned pointer and `UnsafeCell` instead of `RefCell` for the object data. However I would expect the gains to be relatively minor compared to the added unsafety.
