---
title: "Storage Layer Security"
abbrev: "SLS"
category: info

docname: draft-kohbrok-mls-storage-layer-security-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
  - state encryption
  - key exchange
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "kkohbrok/draft-kohbrok-storage-layer-security"
  latest: "https://kkohbrok.github.io/draft-kohbrok-storage-layer-security/draft-kohbrok-mls-storage-layer-security.html"

author:
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad@ratchet.ing
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com

normative:
  RFC8446:
  RFC9420:
  RFC9180:
  RFC6920:
  I-D.ietf-mls-extensions:

informative:

...

--- abstract

This document defines Storage Layer Security (SLS), a component for the
Messaging Layer Security (MLS) protocol that lets the members of an MLS group
encrypt data at rest such that access to the data is tied to group membership.
Members derive a shared storage secret from the MLS key schedule, derive
per-record wrapping keys from it, and authenticate the resulting set of
storage records through a hash tree whose root is agreed upon in the MLS
group context. When the group membership changes, the storage layer is
re-keyed so that new members gain access and removed members lose access to
records created after their removal.

--- middle

# Introduction

MLS {{RFC9420}} provides a group of clients with a continuously evolving
shared secret and an authenticated view of the group's membership. Many
applications built on MLS also need to store data at rest, for example shared
files, group state, or message history, typically on a server that is not a
member of the group. The natural access control policy for such data is the
group membership itself: current members can read the data, everyone else
cannot.

This document defines Storage Layer Security (SLS), an MLS component in the
sense of the safe application interface of {{I-D.ietf-mls-extensions}}. SLS
provides:

- A two-layer encryption scheme in which each stored item is encrypted under
  key material derived from a fresh, item-specific secret, and the
  item-specific secrets are wrapped under per-record keys derived from the
  MLS key schedule.

- An authenticated data structure, the record tree, that commits the group to
  the exact set of storage records. Its root hash is part of the MLS group
  context, so agreement on it follows from MLS itself.

- Rotation of the storage secret, triggered implicitly by changes to the
  group membership and explicitly on request of a member, together with
  deterministic re-encryption of all storage records under new key material.

SLS deliberately does not define how stored items are uploaded to, downloaded
from, or deleted at a storage provider. Those interactions are
application-specific. SLS defines the cryptographic state the group agrees
on and the rules for evolving it.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the TLS presentation language defined in Section 3 of
{{RFC8446}} as used in {{RFC9420}}, as well as the following terms:

Stored item:
: An opaque piece of application data encrypted and stored at rest, for
  example at a storage provider. Stored items are sometimes called blobs.

Storage record:
: A small structure describing one stored item, containing among other
  things the secret the item's encryption key is derived from and a digest
  of the item's ciphertext.

Record tree:
: A left-balanced binary hash tree whose leaves are computed over storage
  records. Its root hash is part of the SLS component state in the group
  context.

Storage epoch:
: The MLS epoch in which the current storage secret was derived. All storage
  records are wrapped under key material of the current storage epoch.

Rotation:
: The transition to a new storage epoch, including the re-encryption of all
  storage records under the new storage secret's key material.

Storage provider:
: An entity, typically a server and typically not a group member, that
  stores encrypted storage records and stored items on behalf of the group.

# Protocol Overview

This section is informative.

SLS separates the encryption of bulk data from the encryption of key
material. A client that wants to add a stored item proceeds as follows:

1. It samples a fresh secret, encrypts the item under key material derived
   from that secret, and computes a digest over the resulting ciphertext.

2. It assembles a storage record containing the secret, the AEAD algorithm,
   the digest, the digest algorithm, and application-defined metadata such
   as the item's location.

3. It encrypts the storage record under a key derived from the current
   storage secret and sends the resulting ciphertext to the group in an
   AppDataUpdate proposal, covered by a commit.

When the commit is processed, each member inserts the new record into the
lowest free leaf of the record tree and updates the root hash in the
component state. Since the component state is part of the group context, all
members agree on the record set, and a member whose local copy diverges can
detect this immediately.

The storage secret is derived from the MLS key schedule via the component
exporter of {{I-D.ietf-mls-extensions}}, in the epoch identified by the
`storage_epoch` field of the component state. Each record is wrapped under
key material derived from that secret, and members retain only the key
material of the current storage epoch.

Any commit that adds or removes members triggers a rotation: the
`storage_epoch` advances to the new epoch and every record is re-encrypted
under key material derived from the new storage secret. The re-encryption
is deterministic, since keys and nonces are derived from the new storage
secret, so every member computes identical ciphertexts locally and no
re-encrypted data needs to be transmitted within the group. A newly added
member derives the new storage secret directly and can decrypt all
records. A removed member cannot derive it. Members can also trigger a rotation
explicitly, without a membership change, via a dedicated operation.

The leaves of the record tree are computed over plaintext storage records
rather than their ciphertexts. This avoids a circular dependency: the root
hash is part of the group context, the group context is an input to the MLS
key schedule, and the key schedule produces the storage secret that the
ciphertexts depend on. Hashing plaintext records also means that rotations
do not modify the record tree. Because every storage record contains a
fresh, high-entropy key, the leaf hashes do not leak information about the
records to non-members.

# The SLS Component

SLS is an MLS component as defined in {{I-D.ietf-mls-extensions}}, with
component ID TBD1 (see {{iana}}). Groups using SLS store the component state
defined in {{component-state}} in the `app_data_dictionary` group context
extension and modify it exclusively through AppDataUpdate proposals carrying
the operations defined in {{operations}}.

All cryptographic operations of the SLS component other than the encryption
of stored items ({{stored-item-encryption}}) use the hash, KDF, and AEAD of
the group's MLS ciphersuite.

## Component State {#component-state}

The SLS component state is the following structure:

~~~ tls-presentation
struct {
    uint64 storage_epoch;
    uint32 n_leaves;
    opaque root_hash<V>;
} StorageState;
~~~

storage_epoch:
: The MLS epoch in which the current storage secret was derived (see
  {{key-schedule}}).

n_leaves:
: The number of leaves of the record tree.

root_hash:
: The root hash of the record tree (see {{record-tree}}), or a zero-length
  string if `n_leaves` is zero.

The component state is created by the first AppDataUpdate proposal for the SLS
component: if no state exists when SLS operations are processed, processing
starts from an initial state with `storage_epoch` set to the epoch the covering
commit was created in, `n_leaves` set to zero, and an empty `root_hash`, and the
operations are applied to that state. Only `add` and `rotate` operations are
valid if there is no component or if `n_leaves` is zero.

Processing SLS operations requires SLS application logic: the updated
component state is computed by that logic rather than carried in
proposals, so every member of a group that uses SLS has to support the
component. Negotiation and enforcement of component support, including
the advertisement of supported components in LeafNodes and the listing
of the SLS component ID as required in the group's `app_components`
component, are handled by the mechanisms of {{I-D.ietf-mls-extensions}}.

> NOTE: This document assumes component support negotiation and
> enforcement rules in {{I-D.ietf-mls-extensions}} that, at the time of
> writing, are still under discussion.

## Key Schedule {#key-schedule}

The storage secret for a storage epoch is exported from the MLS key schedule
of that epoch using the component exporter defined in
{{I-D.ietf-mls-extensions}}:

~~~ pseudocode
storage_secret = SafeExportSecret(sls_component_id)
~~~

All further secrets are derived using the following function, which is
identical to `ExpandWithLabel` from {{Section 8 of RFC9420}} except for the
label prefix:

~~~ pseudocode
ExpandWithLabel(Secret, Label, Context, Length) =
    KDF.Expand(Secret, KDFLabel, Length)
~~~

Where KDFLabel is specified as:

~~~ tls-presentation
struct {
    uint16 length;
    opaque label<V>;
    opaque context<V>;
} KDFLabel;
~~~

And its fields are set to:

~~~ pseudocode
length = Length;
label = "SLS 1.0 " + Label;
context = Context;
~~~

Each storage record encryption uses a wrap secret derived from the storage
secret and the WrapContext defined in {{record-encryption}}:

~~~ pseudocode
wrap_secret = ExpandWithLabel(storage_secret, "wrap", WrapContext,
                              KDF.Nh)
wrap_key    = ExpandWithLabel(wrap_secret, "key", "", AEAD.Nk)
wrap_nonce  = ExpandWithLabel(wrap_secret, "nonce", "", AEAD.Nn)
~~~

The `Context` argument in the derivation of `wrap_secret` is the TLS
serialization of the WrapContext.

Each WrapContext identifies one logical record encryption, so each
`wrap_secret` and its derived key and nonce pair are used for only one
record. Proposal contexts contain a random identifier, while rotation
contexts are deterministic.

All key material derived from a previous storage epoch's storage secret
MUST be deleted once the rotation to a new storage epoch is complete.

## Storage Records {#storage-records}

A storage record describes a single stored item:

~~~ tls-presentation
struct {
    opaque record_secret<V>;
    uint16 record_aead;
    uint8  digest_algorithm;
    opaque record_digest<V>;
    opaque location<V>;
    opaque application_data<V>;
} StorageRecord;
~~~

record_secret:
: The secret from which the stored item's encryption key and nonce are
  derived.

record_aead:
: The AEAD algorithm the stored item is encrypted with, from the HPKE AEAD
  Identifiers registry {{RFC9180}}.

digest_algorithm:
: The hash algorithm used for `record_digest`, from the Named Information
  Hash Algorithm registry {{RFC6920}}.

record_digest:
: A digest, computed with `digest_algorithm`, over the ciphertext of the
  stored item.

location:
: An application-defined locator for the stored item, for example an
  identifier at a storage provider. It MAY be empty, for example when
  stored items are content-addressed by `record_digest`.

application_data:
: Opaque application-defined metadata about the stored item.

The permitted values for `record_aead` are AES-128-GCM, AES-256-GCM, and
ChaCha20Poly1305. The permitted values for `digest_algorithm` are
sha-256, sha-384, and sha-512. Implementations MUST support all permitted
algorithms, so that every valid record is usable by every member. Records
with any other algorithm value, a `record_secret` whose length does not
match `KDF.Nh`, or a `record_digest` whose length
does not match the output length of `digest_algorithm` are invalid and
cause the covering commit to be rejected ({{validation}}). Future
documents may extend the permitted sets.

OPEN QUESTION: How should `location` and `application_data` be defined?
`location` could be a URL, `application_data` could be a component-based
container.

### Stored Item Encryption {#stored-item-encryption}

A stored item is encrypted with the AEAD algorithm identified by
`record_aead`, under a key and nonce derived from `record_secret` using
the group ciphersuite's KDF:

~~~ pseudocode
item_key   = ExpandWithLabel(record_secret, "key", "", AEAD.Nk)
item_nonce = ExpandWithLabel(record_secret, "nonce", "", AEAD.Nn)
~~~

Here, `AEAD.Nk` and `AEAD.Nn` refer to the algorithm identified by
`record_aead`. The AAD is empty. A client creating or updating a storage
record MUST sample a fresh, uniformly random `record_secret` of length
`KDF.Nh` and MUST NOT encrypt more than one plaintext under it. This
single-use requirement carries the security of the construction: reusing
a `record_secret` for a second plaintext repeats both the derived key and
nonce. Deriving the pair from one secret avoids a fixed nonce value that
could be miscopied into a context without the single-use guarantee, and
gives the leaf hashes of the record tree a full `KDF.Nh` of entropy
regardless of the key size of `record_aead`
({{tree-confidentiality}}).

`record_digest` is computed over the resulting ciphertext. Computing the
digest over the ciphertext allows a client to detect a corrupted or
substituted stored item before attempting decryption.

Handling of stored items that exceed the safe message size of the chosen
AEAD, for example by splitting them across multiple storage records or by
applying an application-defined chunking scheme within a single stored
item, is out of scope for this document.

### Record Encryption {#record-encryption}

Storage records are stored and transmitted in encrypted form. Every
encryption derives a key and nonce from the storage secret using a
WrapContext ({{key-schedule}}):

~~~ tls-presentation
enum {
    reserved(0),
    proposal(1),
    rotation(2),
    (255)
} WrapType;

struct {
    WrapType wrap_type;
    select (WrapContext.wrap_type) {
        case proposal:
            opaque wrap_id[32];
        case rotation:
            uint32 leaf_index;
    };
} WrapContext;

struct {
    WrapType wrap_type;
    select (EncryptedStorageRecord.wrap_type) {
        case proposal:
            opaque wrap_id[32];
        case rotation:
            struct {};
    };
    opaque ciphertext<V>;
} EncryptedStorageRecord;
~~~

The `ciphertext` field contains the AEAD encryption of a serialized
StorageRecord under `wrap_key` and `wrap_nonce`, with the serialized
WrapContext as AAD. The WrapContext is populated as follows:

- `proposal`: The encrypting member MUST sample `wrap_id` as a fresh,
  uniformly random 32-byte value for every encryption. This form is used
  for records transmitted in `add` and `update` operations. The `wrap_id`
  is carried in the EncryptedStorageRecord so that a client fetching the
  record from a storage provider can derive the key and nonce without
  access to the covering proposal.

- `rotation`: `leaf_index` is the index of the record's leaf in the record
  tree. This form is produced by rotations. No context fields are carried:
  the storage epoch identifies the key material and the record's position
  identifies the leaf index.

The `wrap_type` field separates proposal and rotation contexts. Proposal
contexts are unique with overwhelming probability because their identifiers
are sampled independently from a 256-bit space. Rotation contexts are unique
within a storage epoch because a rotation encrypts each occupied leaf exactly
once. See {{nonce-key-reuse}} for the resulting bounds.

Since the wrapping key and nonce are derived from the storage secret of the
current storage epoch, a member can decrypt any EncryptedStorageRecord of the
current storage epoch, and only records of the current storage epoch, using
only its current key material.

## Record Tree {#record-tree}

The record tree is a left-balanced binary tree as defined in
{{Section 4.1 of RFC9420}} with `n_leaves` leaves. Each leaf is either
blank or occupied by a StorageRecord. The hash of a node is computed with
the ciphersuite hash over the following structure:

~~~ tls-presentation
enum {
    reserved(0),
    leaf(1),
    parent(2),
    (255)
} SLSNodeType;

struct {
    SLSNodeType node_type;
    select (SLSTreeHashInput.node_type) {
        case leaf:
            optional<StorageRecord> record;
        case parent:
            opaque left_hash<V>;
            opaque right_hash<V>;
    };
} SLSTreeHashInput;
~~~

For a blank leaf, the `record` field is absent. The `root_hash` in the
component state is the hash of the root node, or the zero-length string if
`n_leaves` is zero.

Leaf hashes are computed over plaintext storage records, including the
`record_secret` field, rather than over their encryptions. See
{{tree-confidentiality}} for the confidentiality implications and
{{security-considerations}} for the reasoning behind this design.

The tree grows and shrinks at its right edge:

- When a record is added and no blank leaf exists, the tree is extended by
  one leaf on the right, incrementing `n_leaves`.

- After records have been removed, the tree is truncated: while the
  rightmost leaf is blank and `n_leaves` is greater than zero, the
  rightmost leaf is removed and `n_leaves` is decremented.

Members SHOULD store the record tree, including the plaintext records at
its leaves. A member that stores only the component state can reconstruct
and verify its copy of the records by fetching the encrypted records from a
storage provider, decrypting them, and recomputing the root hash. A member
can likewise verify an individual record against the root hash given the
node hashes of the record's copath. The encoding of such inclusion proofs
is specific to the interface of the storage provider and out of scope for
this document.

## Operations {#operations}

All modifications of the SLS component state are carried in AppDataUpdate
proposals as defined in {{I-D.ietf-mls-extensions}}, with `component_id`
set to the SLS component ID and `op` set to `update`. The `update` field
contains a serialized StorageOperation:

~~~ tls-presentation
enum {
    reserved(0),
    add(1),
    update(2),
    remove(3),
    rotate(4),
    (255)
} StorageOperationType;

struct {
    StorageOperationType op_type;
    select (StorageOperation.op_type) {
        case add:
            EncryptedStorageRecord record;
        case update:
            uint32 leaf_index;
            EncryptedStorageRecord record;
        case remove:
            uint32 leaf_index;
        case rotate:
            struct {};
    };
} StorageOperation;
~~~

An AppDataUpdate proposal for the SLS component with `op` set to `remove`
removes the component from the group entirely, discarding the component
state. How and whether previously stored items are deleted at a storage
provider in that case is up to the application.

### Semantics

add:
: Inserts the record into the record tree. The record is placed in the
  blank leaf with the lowest leaf index. If no leaf is blank, the tree is
  extended ({{record-tree}}). If a single commit covers multiple `add`
  operations, they are processed in the order in which the covering commit
  lists them, each taking the lowest leaf that is still blank. The sender
  does not choose the leaf index.

update:
: Replaces the record at `leaf_index` with the included record. The sender
  MUST sample a fresh `record_secret` for the new record. A fresh secret
  is required even if the stored item itself is unchanged.

remove:
: Blanks the leaf at `leaf_index`, after which the tree is truncated if
  possible ({{record-tree}}). Removing a record does not delete the stored
  item (see {{deletion}}).

rotate:
: Triggers a rotation ({{rotation}}).

### Validation {#validation}

A commit covering SLS operations is invalid, and MUST be rejected, in the
following cases:

- An `update` or `remove` operation references a leaf index that is out of
  range or a blank leaf.

- Two or more `update` or `remove` operations reference the same leaf
  index.

- More than one operation is a `rotate`.

- An `add` or `update` operation carries an EncryptedStorageRecord whose
  `wrap_type` is not `proposal`.

- Two `add` or `update` operations carry the same `wrap_id`.

- The `ciphertext` of an `add` or `update` operation does not decrypt
  under the key, nonce, and AAD determined by its WrapContext, or the
  resulting plaintext does not parse as a StorageRecord. Members
  necessarily decrypt every proposal-carried record while processing the
  covering commit, because the record tree commits to plaintext records.
  These checks are therefore objective and available to every member.

- A decrypted StorageRecord violates the algorithm requirements of
  {{storage-records}}: its `record_aead` or `digest_algorithm` is not one
  of the permitted values, the length of its `record_secret` does not
  match `KDF.Nh`, or the length of its `record_digest`
  does not match the output length of `digest_algorithm`.

- The commit covers both an SLS `add`, `update`, `remove`, or `rotate`
  operation and a proposal that adds or removes group members. This
  restriction keeps the interaction between membership changes and storage
  changes simple. It may be lifted in a future version of this document.

- The commit covers a `rotate` operation but does not include an
  UpdatePath. Without an UpdatePath, the `commit_secret` is all-zero
  ({{Section 12.4 of RFC9420}}) and an adversary in possession of the
  previous epoch's secrets could derive the new storage secret, defeating
  the purpose of the rotation.

- An SLS operation other than `remove` was sent by an external sender.
  Applications MAY further restrict which external senders are allowed to
  send `remove` operations.

What receivers cannot verify is that a `record_secret` is fresh and that
`record_digest` matches an item actually retrievable from a storage
provider. Records are, however, attributable: every AppDataUpdate proposal
is authenticated by MLS, so a record that turns out to be unusable can be
traced to its signer by any member (see {{security-considerations}}).

### Processing

SLS operations are processed in the order in which the covering commit
lists them, after the default proposal types as specified in
{{I-D.ietf-mls-extensions}}, with the exception that a `rotate` operation
is processed last. After all operations have been applied, each member
recomputes `n_leaves` and `root_hash` and updates the component state. Note
that proposals do not carry the new root hash. It is an output of
processing, computed independently by every member.

If the commit changes the group membership, an implicit rotation is
processed last instead ({{rotation}}).

## Rotation {#rotation}

A rotation moves the group to a new storage epoch. Rotations are triggered:

- implicitly, by any commit that adds or removes group members, including
  external commits, or

- explicitly, by a `rotate` operation.

A rotation is processed as follows:

1. Set `storage_epoch` in the component state to the epoch created by the
   covering commit.

2. Derive the new storage secret ({{key-schedule}}) in the new epoch.

3. For every occupied leaf `i` of the record tree, where the record tree is
   in the state reached after all other operations covered by the commit
   have been processed, encrypt the record as an EncryptedStorageRecord
   with `wrap_type` set to `rotation`, using the key, nonce, and AAD derived
   from the WrapContext with `leaf_index` set to `i`
   ({{record-encryption}}).

4. Delete the storage secret and all derived key material of the previous
   storage epoch.

Rotation does not modify the record tree: `n_leaves` and `root_hash` are
unchanged. Since step 3 is deterministic, every member that holds the
plaintext records computes an identical set of ciphertexts, and the
re-encrypted records do not need to be transmitted within the group.

The member that created the commit SHOULD make the re-encrypted records
available to the storage provider promptly. Any other member MAY do so as
well. Because the ciphertexts are deterministic, concurrent uploads are
idempotent. Note that the committer of an external commit joined the group
through that commit and does not hold the plaintext records, so it cannot
perform the upload. In that case the existing members are responsible for
it.

Members removed by the rotation's covering commit cannot derive the new
storage secret. Members added by it can, which is what gives new members
access to the stored data (see {{joining}}).

## Joining a Group {#joining}

A new member learns the component state from the group context included in
the Welcome or, for external commits, the GroupInfo. Because every commit
that adds members triggers an implicit rotation, a new member MUST verify
that `storage_epoch` equals the epoch it joined. A mismatch indicates that
other members violated this specification.

The new member can then derive the storage secret of the current storage
epoch, fetch the encrypted records (for example from a storage provider),
decrypt them, and verify the reconstructed record tree against `root_hash`.
Until a previously existing member has uploaded the re-encrypted records of
the current storage epoch, the fetched records may still be those of a
previous storage epoch, which the new member cannot decrypt. The new member
can only wait for the upload in that case.

# Operational Considerations

## The Storage Provider

A storage provider stores, at minimum, the current EncryptedStorageRecord
for each occupied leaf index and the stored items themselves. Because
rotations replace all record ciphertexts at once, providers SHOULD track
which storage epoch a stored record ciphertext belongs to and SHOULD
replace the record set of a group atomically per storage epoch, so that
clients never observe a mix of ciphertexts from different storage epochs.

A storage provider cannot compute leaf hashes or verify the record tree,
since leaves are computed over plaintext records. If the application makes
the provider an external sender of the group, the provider can remove
records, for example to enforce retention policies, by sending `remove`
operations. Such removals take effect only once a member commits them, and
they are visible to all members through the changed component state.

## Coordinating Uploads

The application SHOULD ensure that the upload of a stored item and the
commit covering the corresponding `add` or `update` operation are
coordinated, for example by uploading the stored item before sending the
proposal, so that no record ever references a stored item that other
members cannot retrieve.

The wrapped record itself also has to reach the provider. A leaf index is
assigned to an `add` operation only when the covering commit is processed,
so the sender of an `add` or `update` operation SHOULD upload the
EncryptedStorageRecord for its assigned leaf once the covering commit has
been applied. Any other member MAY do so instead. All members hold the
identical ciphertext after processing.

If AppDataUpdate proposals are sent as PrivateMessage, the storage provider
does not learn which operations took place. Applications that rely on the
provider for garbage collection need to signal deletions to it separately.

# Security Considerations {#security-considerations}

## Access to Stored Data

SLS ties the ability to decrypt storage records to knowledge of the current
storage secret, which is derived from the MLS key schedule and therefore
available exactly to the members of the group in the storage epoch.

Members added to the group gain access to all storage records, including
records created before they joined. In this respect stored data behaves
differently from MLS messages, whose keys are not retroactively available
to new members. Applications for which this is undesirable need to
partition data across groups or apply additional access control above SLS.

Members removed from the group cannot derive the storage secret of any
subsequent storage epoch. However, a removed member knows every record
secret,
and potentially every stored item, that existed while it was a member.
Rotation therefore protects records created or updated after the removal.
It does not retroactively protect data the removed member already had
access to. The same applies to an adversary that compromised a member's
state: rotation with an UpdatePath denies the adversary the new storage
secret, but every record secret of the compromised storage epoch, and thus
every stored item referenced at that time, must be considered exposed.
Fully recovering the confidentiality of a stored item after a compromise
requires an `update` operation for its record: a fresh record secret and a
re-encryption of the stored item itself.

## Forward Secrecy

Members hold the key material of exactly one storage epoch and MUST delete
the previous storage epoch's key material when processing a rotation.
Forward secrecy of the storage layer is therefore granular to rotations
rather than to MLS epochs: an adversary that compromises a member learns
the records of the current storage epoch, regardless of how many MLS epochs
it spans. Applications can bound this window by sending `rotate` operations
periodically, at the cost of one re-encryption and upload of all records
per rotation.

## Deletion {#deletion}

Removing a record from the record tree does not erase anything by itself.
Deleting a stored item requires all of the following, in combination:

- a `remove` operation, so that the group no longer vouches for the record,

- deletion of the stored item's ciphertext by the storage provider,

- deletion of the record and its key from members' local storage, and

- a rotation, so that the wrapping ciphertext of the removed record becomes
  undecryptable even if a copy of it survives at the provider.

None of these steps protects against a member or former member that
retained a copy of the stored item.

## Confidentiality of the Record Tree {#tree-confidentiality}

Leaf hashes are computed over plaintext storage records. A leaf hash is
nevertheless not a useful oracle for an outsider: every storage record
contains a fresh, uniformly random `record_secret` of `KDF.Nh` bytes, so
an adversary cannot confirm a guess of the remaining record
fields by recomputing the hash.

## Nonce and Key Reuse {#nonce-key-reuse}

Each storage record encryption uses a key and nonce derived from a
WrapContext that identifies one logical encryption. The `wrap_type` field
separates proposal contexts from rotation contexts. A rotation occurs once
per storage epoch and encrypts each occupied leaf once, so its contexts are
unique. The deterministic rotation contexts allow every member to reproduce
the same ciphertexts without transmitting them within the group.

Proposal context uniqueness is probabilistic. An honest member samples an
independent, uniformly random 256-bit `wrap_id` for every encryption. For q
proposal encryptions in one storage epoch, the probability that any two
identifiers collide is at most q * (q - 1) / 2^257. For example, even at
q = 2^32 the probability is less than 2^-193. This bound includes
encryptions for proposals that are never committed.

For distinct WrapContexts, the security of the derived key and nonce pairs
relies on the pseudorandom function security of the KDF. A collision in only
the nonce does not cause nonce reuse because each context also derives a
separate key. Reuse of a `wrap_id` within the same storage epoch, however,
repeats both the key and the nonce and can compromise confidentiality and
integrity. Implementations therefore MUST generate `wrap_id` values using a
cryptographically secure source of randomness.

Stored items are encrypted under a key and nonce derived from a
single-use `record_secret`. As with `wrap_id` values, reusing a
`record_secret` repeats both the key and the nonce, so the single-use
requirement in {{stored-item-encryption}} carries the security of the
construction.

## Malformed Records

Records that do not decrypt, do not parse, or violate the algorithm
requirements are rejected at validation time, since every member decrypts
every proposal-carried record while processing the covering commit
({{validation}}). A member can still send a record that is well-formed but
useless: one whose secret is stale or reused, or whose digest and location
match no retrievable stored item. Other members can only detect this upon
use, and the AppDataUpdate proposal that introduced the record identifies
its sender through MLS authentication. Applications SHOULD define how such
misbehavior is handled. This document intentionally does not attempt to
make correct encryption verifiable by non-members.

## Metadata

A storage provider observes the number of records, the sizes of records and
stored items, and the timing of uploads, rotations, and deletions.
Proposal `wrap_id` values are uniformly random and do not reveal the sender,
the MLS epoch in which the record was created, or a per-sender encryption
count. Applications SHOULD consider padding stored items and batching
operations if this metadata is sensitive.

# IANA Considerations {#iana}

This document requests the addition of one new entry to the MLS Component
Types registry defined in {{I-D.ietf-mls-extensions}}:

- Value: TBD1
- Name: storage_layer_security
- Where: ES, GC
- Recommended: Y
- Reference: This document

The Where value reflects that SLS derives secrets via the component
exporter and stores component data in the GroupContext.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
