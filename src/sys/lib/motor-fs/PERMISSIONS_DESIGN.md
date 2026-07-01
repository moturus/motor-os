# Motor FS — File/Directory Permissions Design

Status: **implemented** (Phase 0 trait wiring → Phase 1 Mode S → Phase 2 Mode E,
per §9). Enforcement lives in `motor-fs/src/fs.rs` (`require_access` + the §5
insertion points), the txn logic in `txn.rs` (`do_set_permissions_txn`), and the
types in `async-fs/src/filesystem.rs`. Ungated in v1: `metadata`, `name`,
`get_parent` (each still carries the `role` param for a future phase).
Audience: an engineer (human or LLM) maintaining or extending this feature.

This document specifies how to add `r`/`w`/`x` permissions to Motor FS. It is
self-contained: it records the on-disk encoding, the type definitions, the
authority model for changing permissions, the enforcement points, the required
API changes, and a test plan. Code references include current line numbers,
which may drift — treat the *named items* (structs, fields, methods) as the
stable anchors.

---

## 1. Goals and model

Motor OS does not have users, so Motor FS permissions are **not per-user**. They are
**global per privilege role**. There are exactly three roles, ordered by
privilege:

```
System  >  Interactive  >  None
(root-like)  (logged-in)    (least privileged)
```

Each filesystem entry (file or directory) stores **one permission value per
role** — three values total. There is no owner/group/other distinction and no
per-user ACL (the layout leaves room to add ACLs later; see §10).

Each per-role permission is one of **five** values. `r` is a gate: if reading is
not allowed, then neither writing nor execution is allowed. The legal values:

| Value | r | w | x | Meaning |
|-------|---|---|---|---------|
| `Rwx` | ✓ | ✓ | ✓ | full access |
| `Rx`  | ✓ |   | ✓ | read + execute |
| `Rw`  | ✓ | ✓ |   | read + write |
| `R`   | ✓ |   |   | read only |
| `None`|   |   |   | no access |

Note the value space is a **lattice, not a chain**: `Rx` and `Rw` are
incomparable (each has a permission the other lacks). "Narrowing" therefore
means *moving to a subset*, not "to a smaller number" — see §4 and `can_narrow_to`.

```
        Rwx
       /    \
     Rx      Rw
       \    /
         R
         |
        None
```

### Permission meaning per entry kind

| Permission | File | Directory |
|------------|------|-----------|
| `r` (read) | read contents | gate for `w`/`x` (no standalone directory op) |
| `w` (write)| modify contents (write/resize/truncate) | create / delete / rename child entries |
| `x` (exec) | may be executed as a program | list / traverse / look up entries |

For directories, **listing, traversal, and name lookup all map to the single
`x` bit** (`stat`/`get_first_entry`/`get_next_entry` require `x`), and
modification maps to `w` (`create`/`delete`/`rename` require `w`). Because `r`
gates `x`, a directory needs at least `Rx` to be listed. Consequences of the
model:
- A `Rw` directory (write, no execute) is a **write-only "drop-box"**: entries
  can be created/deleted but not listed or looked up by name.
- A `Rx` directory (execute, no write) is **listable but immutable**.
- "Traverse a known name" cannot be separated from "list all entries" — both
  require `x` (unlike Unix, which splits them across `x` and `r`). This is an
  intentional simplification.

### Cross-role monotonicity

A less-privileged role may never hold a permission that a more-privileged role
lacks. Every entry must satisfy the invariant
`access(None) ⊆ access(Interactive) ⊆ access(System)`, where `⊆` is the per-bit
subset (the same relation `can_narrow_to` tests) applied independently to `r`,
`w`, and `x`. In words: "if System cannot write, neither can Interactive or
None"; "if None can execute, so can Interactive and System".

This is enforced on every change (§4a) and validated at creation (§6.2). It is
what turns the System byte into a true whole-entry ceiling and gives the sealing
guarantee its teeth (§4).

### Zero means "everything allowed"

The encoding is chosen so that an all-zero permission byte decodes to `Rwx`.
This makes the feature backward-compatible for free: every existing entry, and
every entry produced by the current format/creation paths (which zero
`Metadata`), is born fully permissive. No migration, no superblock version bump
is required.

---

## 2. On-disk storage

Permissions live in the existing `Metadata` struct, which is embedded in every
`DirEntryBlock` and already returned to callers by `MotorFs::metadata()`. The
struct is defined in the **`async-fs`** crate:

- File: `src/sys/lib/async-fs/src/filesystem.rs`
- Struct: `Metadata` (currently around line 112), `#[repr(C, align(8))]`, `Pod`,
  pinned to **128 bytes** by `const _: () = assert!(128 == size_of::<Metadata>())`.

We repartition three bytes out of the existing `_reserved` field. **No size
change, no layout change for any other field.**

### Before

```rust
pub struct Metadata {
    pub size: u64,                 // @0
    pub created: Timestamp,        // @8
    pub modified: Timestamp,       // @20
    pub accessed: Timestamp,       // @32
    kind: u8,                      // @44
    _reserved: [u8; 11],           // @45..56
    pub user_extensions: [u8; 72], // @56..128  "Permissions, ACL, whatever."
}
```

### After

```rust
pub struct Metadata {
    pub size: u64,                 // @0
    pub created: Timestamp,        // @8
    pub modified: Timestamp,       // @20
    pub accessed: Timestamp,       // @32
    kind: u8,                      // @44
    perms: [u8; 3],                // @45..48   one AccessPermissions byte per Role; see below
    _reserved: [u8; 8],            // @48..56   (was [u8; 11])
    pub user_extensions: [u8; 72], // @56..128  UNCHANGED, byte-for-byte
}
```

`perms` is a **single 3-byte array** (not three named fields). Indexing by
`Role as usize` keeps every call site a single lookup, and the `Role`
discriminants are chosen so **index == privilege rank** (see §3). `user_extensions`
keeps the same offset (56), so any future ACL work is unaffected.

**Slot mapping (document this on the field):**

```
perms[0] = None role
perms[1] = Interactive role
perms[2] = System role
```

> Note: this makes the raw byte order read `None, Interactive, System` in a hex
> dump (reverse of "natural" order). That is the deliberate cost of making
> `index == privilege`, which keeps `may_set` (§4) a one-line comparison.

**Important:** `perms` must stay a raw `[u8; 3]`, **not** `[AccessPermissions; 3]`. `AccessPermissions`
has invalid bit patterns (any byte > 4), so it cannot be `Pod`/`Zeroable`
safely; a corrupt or legacy byte reinterpreted as an enum would be UB. Always
decode through the validating `AccessPermissions::try_from` (§3).

### Other required edits in `filesystem.rs`

- `Metadata::zeroed()` (around line 142) lists fields explicitly; add
  `perms: [0; 3]` and change `_reserved: [0; 11]` → `_reserved: [0; 8]`.
- The 128-byte `assert!` must still pass (it will; the repartition is size-neutral).

No changes are needed in `motor-fs/src/layout.rs`: `DirEntryBlock` embeds
`Metadata` by value, so its layout and the `BLOCK_SIZE == size_of::<DirEntryBlock>()`
assertion are unaffected. The format path (`Superblock::format`) and
`DirEntryBlock::init_child_entry` zero the metadata, which now means "all roles
`Rwx`" — exactly the desired default (but see §6 for setting non-default perms
at creation).

---

## 3. New types (`async-fs`, next to `Metadata`)

`AccessPermissions` and `Role` are placed in `async-fs` because `Metadata` lives there and
callers need them to interpret `metadata()`. Follow the existing cfg-branched
error pattern used by `EntryKind`'s `TryFrom<u8>` (filesystem.rs:19–45):
`InvalidData` is `std::io::ErrorKind::InvalidData` under `std`, and
`moto_rt::Error::InvalidData` otherwise.

```rust
/// Per-role permission value. `r` gates `w` and `x`. Zero == `Rwx`.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessPermissions {
    Rwx  = 0,   // zero => full access (legacy/format default)
    Rx   = 1,
    Rw   = 2,
    R    = 3,
    None = 4,
}

impl AccessPermissions {
    /// (read, write, execute)
    pub fn triple(self) -> (bool, bool, bool) {
        match self {
            AccessPermissions::Rwx  => (true,  true,  true),
            AccessPermissions::Rx   => (true,  false, true),
            AccessPermissions::Rw   => (true,  true,  false),
            AccessPermissions::R    => (true,  false, false),
            AccessPermissions::None => (false, false, false),
        }
    }

    pub fn can_read(self)    -> bool { self.triple().0 }
    pub fn can_write(self)   -> bool { self.triple().1 }
    pub fn can_execute(self) -> bool { self.triple().2 }

    /// True iff `target`'s permission set is a subset of `self`'s, i.e. `self`
    /// may be *narrowed* to `target` without granting anything new.
    /// Rejects e.g. Rx -> Rw (would drop x and add w).
    pub fn can_narrow_to(self, target: AccessPermissions) -> bool {
        let (sr, sw, sx) = self.triple();
        let (tr, tw, tx) = target.triple();
        (!tr || sr) && (!tw || sw) && (!tx || sx)
    }

    /// Per-bit intersection of two permissions. ANDing two r-gated values keeps
    /// the r-gate, so the result is always a valid `AccessPermissions`. Used to clamp
    /// lower roles when a higher role is narrowed (§4a, cascade).
    pub fn meet(self, other: AccessPermissions) -> AccessPermissions {
        let (ar, aw, ax) = self.triple();
        let (br, bw, bx) = other.triple();
        Self::from_triple(ar && br, aw && bw, ax && bx)
    }

    /// Build an `AccessPermissions` from an r-gated `(r, w, x)` triple. Internal helper;
    /// only ever fed gated triples (raw disk bytes go through `try_from`).
    fn from_triple(r: bool, w: bool, x: bool) -> AccessPermissions {
        match (r, w, x) {
            (true,  true,  true)  => AccessPermissions::Rwx,
            (true,  false, true)  => AccessPermissions::Rx,
            (true,  true,  false) => AccessPermissions::Rw,
            (true,  false, false) => AccessPermissions::R,
            _                     => AccessPermissions::None,
        }
    }
}

impl TryFrom<u8> for AccessPermissions {
    type Error = /* crate Result error type, per EntryKind pattern */;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(AccessPermissions::Rwx),
            1 => Ok(AccessPermissions::Rx),
            2 => Ok(AccessPermissions::Rw),
            3 => Ok(AccessPermissions::R),
            4 => Ok(AccessPermissions::None),
            x => { log::error!("Corrupt AccessPermissions byte: {x}"); Err(/* InvalidData */) }
        }
    }
}
```

```rust
/// Privilege role. Discriminant == array index into `Metadata::perms`
/// AND == privilege rank (higher = more privileged).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    None        = 0,
    Interactive = 1,
    System      = 2,
}

impl TryFrom<u8> for Role {
    type Error = /* crate Result error type */;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Role::None),
            1 => Ok(Role::Interactive),
            2 => Ok(Role::System),
            x => { log::error!("Corrupt Role byte: {x}"); Err(/* InvalidData */) }
        }
    }
}
```

### `Metadata` accessors

```rust
impl Metadata {
    /// Decoded permission for `role`. Errors only on a corrupt on-disk byte.
    pub fn access(&self, role: Role) -> Result<AccessPermissions> {
        AccessPermissions::try_from(self.perms[role as usize])
    }

    /// Overwrite the raw permission byte for `role`. Callers must have already
    /// authorized the change via `may_set` (see §4); this is the unchecked
    /// setter used by the txn layer.
    pub fn set_access(&mut self, role: Role, access: AccessPermissions) {
        self.perms[role as usize] = access as u8;
    }
}
```

### Authority policy function

```rust
/// May a caller acting as `caller` change role `target`'s permission from
/// `old` to `new`? This governs **authority only**; the cross-role monotonicity
/// invariant (§4a) is a separate constraint applied by the txn layer (cap +
/// cascade).
///   - target strictly below caller : any change (widen or narrow)
///   - target == caller (own byte)  : narrow only
///   - target strictly above caller : forbidden
pub fn may_set(caller: Role, target: Role, old: AccessPermissions, new: AccessPermissions) -> bool {
    use core::cmp::Ordering::*;
    match (caller as u8).cmp(&(target as u8)) {
        Greater => true,
        Equal   => old.can_narrow_to(new),
        Less    => false,
    }
}

/// True iff `perms` (indexed by `Role`) satisfies cross-role monotonicity:
/// `perms[None] ⊆ perms[Interactive] ⊆ perms[System]` (§1, §4a). Used to
/// validate the initial permissions passed to `create_entry`.
pub fn perms_monotonic(perms: [AccessPermissions; 3]) -> bool {
    perms[Role::System as usize].can_narrow_to(perms[Role::Interactive as usize])
        && perms[Role::Interactive as usize].can_narrow_to(perms[Role::None as usize])
}
```

---

## 4. Authority model for changing permissions

Privilege order: **System > Interactive > None**. For caller `C` changing the
byte of target role `T`:

| Caller ↓ \ Target → | System byte | Interactive byte | None byte |
|---------------------|-------------|------------------|-----------|
| **System**          | narrow-only | any (widen/narrow)| any       |
| **Interactive**     | forbidden   | narrow-only      | any       |
| **None**            | forbidden   | forbidden        | narrow-only |

This table is captured by `may_set` (§3) and governs **authority** only. The
rule "the System permission can never be widened" is **emergent**, not a special
case: the only role allowed to touch the System byte is System itself, and for
its own byte the rule is narrow-only. Do **not** implement it as a separate
check. Every change must *additionally* preserve cross-role monotonicity (§4a).

### 4a. Cross-role monotonicity enforcement

Beyond the authority check, every change must keep
`access(None) ⊆ access(Interactive) ⊆ access(System)` (§1). A single
`set_permissions(caller, target, new)` maintains it in one pass:

1. **Authorize:** `may_set(caller, target, old, new)` (§3); reject if false.
2. **Cap (widen direction):** `target`'s ceiling is the immediately-higher role
   (`Role` index `target + 1`; `System` has none). If the ceiling cannot be
   narrowed to `new` (`!ceiling.can_narrow_to(new)`, i.e. `new ⊄ ceiling`),
   reject with `PermissionDenied`. Reject rather than silently clamp, so a widen
   never under-grants unnoticed. (A pure narrow can never trip this:
   `new ⊆ old ⊆ ceiling` already.)
3. **Write** `target = new`.
4. **Cascade (narrow direction):** clamp every strictly-lower role `L` to
   `access(L).meet(new)`. This only removes bits, always stays within the
   caller's authority (strictly-lower roles are below the caller), and one pass
   suffices — the lower roles were already nested, so clamping each to
   `meet(old_L, new)` preserves their order.

Both the cap and the cascade can fire in one call (e.g. setting a lower role to
a value incomparable to its old one). The cascade is why narrowing the System
byte restricts every role at once.

### Sealing / immutability consequence

With the invariant enforced, the **System byte is a true whole-entry ceiling**:
no role can exceed it, and nobody can ever widen it (emergent, above).
Therefore:

- **Sealing works.** Narrowing the System byte's `w` off cascades every role's
  `w` off (step 4) and can never be undone, so the entry becomes permanently
  read-only to *all* roles — a real `chattr +i`. Narrowing System to `None`
  makes it permanently inaccessible to every role.
- Narrowing a *lower* role (Interactive or None) is **not** permanent: a
  higher-privileged role may re-widen it, up to the System ceiling.
- Sealing contents does not prevent deletion — deletion is gated by the
  **parent directory's** `w`. To make an entry undeletable, seal the parent
  directory's System byte too.

---

## 5. Access enforcement (`read`/`write`/...) — Mode S vs Mode E

Enforcing access requires knowing **which role the caller is acting as**. That
role is a trusted input supplied from above the FS as an explicit `role: Role`
parameter on the `FileSystem` methods (§9, decision 1). Two implementation
modes, sequenced per the §9 plan (Phase 0 wiring → Mode S → Mode E).

### Mode S — store, report, and govern changes (recommended first increment)

- The FS **stores** the three bytes and **reports** them via `metadata()`
  (already returns `Metadata` by value, so reporting is free once populated).
- The FS **enforces `may_set`** in `set_permissions` and `create_entry`. This is
  valuable even without access enforcement: it makes the on-disk narrow-only
  invariant — especially System-byte monotonicity — impossible to violate
  regardless of buggy callers.
- The FS does **not** gate `read`/`write`/etc. in Mode S. The `role` parameter is
  already present (Phase 0) but unused on the data path until Mode E; access
  enforcement is done above the FS in the meantime.

### Mode E — full in-FS access enforcement (follow-up)

Add access checks keyed off the caller's own role byte. Use
`ErrorKind::PermissionDenied`. Insertion points (function : required permission
: which entry's byte):

The check is a `require_access(role, entry, Need)` helper (`Need::{Read, Write,
Execute}`) keyed off the caller's own role byte.

| Method (`motor-fs/src/fs.rs`) | Needs | Byte checked |
|-------------------------------|-------|--------------|
| `read`                        | `r`   | the file |
| `write`, `resize`             | `w`   | the file |
| `create_entry`                | `w`   | the **parent dir** |
| `delete_entry`                | `w`   | the **parent dir** |
| `move_entry`                  | `w`   | **old** parent dir AND **new** parent dir |
| `stat`, `get_first_entry`, `get_next_entry` | `x` | the dir being listed / traversed |

Notes:
- **Directory traversal/listing/lookup requires `x`**, not `r`: `stat`,
  `get_first_entry`, and `get_next_entry` check the directory's execute bit
  (a directory therefore needs at least `Rx` to be listed or looked up in).
- `create`/`delete`/`rename` are gated by the **parent directory's** `w` only,
  **not** `x`. Their internal existence checks use an *unenforced* `lookup_child`
  helper (not the `x`-gated `stat`), so write alone suffices. (Consequence: a
  `Rw` directory is a write-only "drop-box" — entries can be added/removed but
  not listed; see §1.)
- `copy_file_range` is composed of `self.read` + `self.write`; those enforce and
  forward the caller role, so it is covered transitively.
- **Execute (`x`):** on a **directory** it is enforced (traversal/listing/lookup,
  above). On a **file** it is store-and-report only — the FS never executes
  anything, so file `x` is metadata for an exec-time consumer above the FS.
- `metadata`, `name`, and `get_parent` are **ungated** in v1 (each still carries
  the `role` param). Revisit if a later phase needs them gated.

---

## 6. API changes

These touch the `FileSystem` trait (`async-fs/src/filesystem.rs`) and its impl
in `motor-fs/src/fs.rs` + the txn layer (`motor-fs/src/txn.rs`). Changing the
trait is a breaking change for all impls; updating non-FS impl sites is out of
scope for this crate's work but must be kept in mind.

### 6.1 New: `set_permissions`

Add to the `FileSystem` trait:

```rust
/// Change one role's permission on `entry_id`, acting as `caller`.
/// Enforces `may_set`; returns PermissionDenied if not allowed.
async fn set_permissions(
    &mut self,
    caller: Role,
    entry_id: EntryId,
    target: Role,
    access: AccessPermissions,
) -> Result<()>;
```

Implement via a new `Txn::do_set_permissions_txn` mirroring the existing
`do_move_entry_txn` structure (`txn.rs:190`). It runs the §4a algorithm:
1. Load + `validate_entry` the entry block.
2. `old = metadata.access(target)?`.
3. **Authorize:** if `!may_set(caller, target, old, access)` → `Err(PermissionDenied)`.
4. **Cap:** if `target` has a higher role `H` and
   `!metadata.access(H)?.can_narrow_to(access)` → `Err(PermissionDenied)`.
5. `metadata.set_access(target, access)`.
6. **Cascade:** for each strictly-lower role `L`,
   `metadata.set_access(L, metadata.access(L)?.meet(access))`.
7. `metadata.modified = Timestamp::now()`; `txn.commit()`.

### 6.2 Changed: `create_entry`

`create_entry` must accept the initial permissions for the new entry and the
caller's role, so creation authority matches §4:

```rust
async fn create_entry(
    &mut self,
    caller: Role,
    parent_id: EntryId,
    kind: EntryKind,
    name: &str,
    perms: [AccessPermissions; 3], // indexed by Role; convenience: [AccessPermissions::Rwx; 3] = default
) -> Result<EntryId>;
```

Authorization at creation, per role, plus cross-role monotonicity
(`perms_monotonic(perms)`, §4a):
- for the caller's **own or a strictly-lower** role: any value is allowed (the
  starting point is the `Rwx` default, and `Rwx` narrows to anything);
- for a **strictly-higher** role: the byte must be left `Rwx` — the caller
  cannot restrict what it does not control. (E.g. an `Interactive` creator
  always leaves the `System` byte `Rwx`.)

> Do **not** implement this as `may_set(caller, role, AccessPermissions::Rwx, perms[role])`
> for every role: `may_set` returns `false` for a strictly-higher target even
> when the requested value equals its unchanged `Rwx` default, which would wrong-
> ly reject a lower-privileged caller creating with the default perms. Use the
> "higher role must equal `Rwx`" rule above instead.

Reject the whole creation with `PermissionDenied` if any per-role check fails or
the array is non-monotonic (creation validates and rejects; it does not cascade
or clamp). Then `init_child_entry` (`layout.rs:820`) writes the three bytes into
the new entry's metadata (instead of leaving them zero — though zero would also
mean `Rwx`).

> Minimal-churn alternative if the trait signature change is too invasive for a
> first cut: keep `create_entry` as-is (all entries born `[Rwx; 3]`) and require
> a follow-up `set_permissions` call. This is racier and cannot express
> "create already-restricted"; prefer adding the parameter.

### 6.3 `metadata()` already carries permissions

`MotorFs::metadata()` (`fs.rs:413`) returns `Metadata` by value, so once `perms`
is populated, callers can read it via `Metadata::access(role)`. No signature
change needed for reporting.

---

## 7. What does NOT change

- B+ tree (`bplus_tree.rs`), block allocation / freelist (`Superblock`),
  transaction log (`txn_log.rs`), name hashing (`city_hash.rs`), inline-file
  storage, directory hash-collision lists.
- `DirEntryBlock` layout and all of its size assertions.
- On-disk format version (no bump required); old images open with all entries
  fully permissive.
- `user_extensions` (still 72 bytes at offset 56), reserved for future ACLs.

---

## 8. Test plan

Add to `motor-fs/src/tests.rs` (and unit tests in `async-fs` for the pure types):

**Pure type tests (`async-fs`):**
1. `AccessPermissions::try_from` round-trips 0..=4; rejects 5..=255 with `InvalidData`.
2. Zeroed byte decodes to `AccessPermissions::Rwx`; `Metadata::zeroed().access(role) == Rwx`
   for all roles.
3. `triple()` correctness for all five values.
4. `can_narrow_to`: lattice cases, especially `Rx`↔`Rw` both reject each other;
   `Rwx` narrows to all; `None` narrows only to itself; `R` narrows only to
   `None`/`R`.
5. `meet`: per-bit intersection over all 25 pairs; result is always a valid
   `AccessPermissions`; `meet` is commutative and `a.meet(a) == a`.
6. `perms_monotonic`: accepts nested arrays (e.g. `[R, Rw, Rwx]`), rejects any
   inversion (e.g. `[Rwx, R, R]`) and any incomparable adjacent pair
   (e.g. `[None, Rx, Rw]`).
7. `may_set` — exhaustively over the 3×3 caller/target matrix and both
   directions; assert it matches the §4 table. Specifically verify the System
   byte is non-wideable even when caller == System.

**FS integration tests (`motor-fs`):**
8. Create an entry with default perms → `metadata().access(role) == Rwx` for all
   roles; persists across flush + reopen.
9. Create with restricted (still monotonic) perms as System → values persist
   across reopen; creation with a non-monotonic array is rejected.
10. `set_permissions` authority: own-byte narrow succeeds; own-byte widen fails;
    lower-role narrow succeeds; higher-role change fails — asserting
    `PermissionDenied`.
11. `set_permissions` cap: widening a lower role beyond its higher-role ceiling
    is rejected (`PermissionDenied`); widening up to the ceiling succeeds.
12. `set_permissions` cascade: narrowing System (e.g. drop `w`) clamps
    Interactive and None to lose `w` too, in one call.
13. Sealing: after narrowing System's `w` off, every role reports no `w`, and
    every attempt to re-grant `w` to any role fails permanently.
14. Backward compat: format an image, manually zero the `perms` bytes (or open a
    pre-feature image), confirm all roles read `Rwx`.
15. (Mode E only) `read` denied when caller's role byte lacks `r`; `write`/
    `resize` denied without `w`; `create`/`delete` denied without parent-dir
    `w`; `move` checks both parents; `stat`/`get_first_entry`/`get_next_entry`
    denied without parent-dir **`x`** (an `Rx` dir lists, a `Rw` dir does not,
    an `R` dir does not).

---

Invariant to uphold throughout: **a lower role's permissions must never be wider
than a higher role's** (§1, §4a) — enforced on every change and validated at
creation.

---

## 10. Future-proofing / rejected alternatives

- **Per-user ACLs:** out of scope (permissions are global-per-role by
  requirement). The untouched 72-byte `user_extensions` block is the intended
  home for a future versioned ACL/xattr record if that requirement ever changes.
- **Individual `r`/`w`/`x` bits instead of the 5-value enum:** rejected. The
  enum makes the invalid states (`w`/`x` without `r`) unrepresentable by
  construction, matching the "r gates w,x" rule.
- **Deny-bitmask encoding (`Rwx=0, Rx=0b010, Rw=0b100, R=0b110, None=0b111`):**
  considered. It makes `can_narrow_to` a single bit op (`new & old == old`) but
  reintroduces in-range invalid bytes (1,3,5) to validate and reads as "bits"
  rather than "a value." Rejected in favor of the sequential enum; revisit only
  if the bit-op ergonomics ever matter.
- **`_reserved` vs `user_extensions` for storage:** chose `_reserved` (per the
  feature request) to keep `user_extensions` fully intact for ACLs.
```
