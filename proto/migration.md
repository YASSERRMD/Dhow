# Migration Notes

> Version 1.0

This document describes how to migrate between versions of the Dhow wire format.

## v1.0 (initial release)

No migration needed. This is the first version of the wire format.

## Future migrations

When the format version is bumped:

1. The sender writes the new version byte.
2. The receiver checks the version byte and rejects unknown versions.
3. Reserved fields allow backward-compatible extensions without a version bump.
4. Breaking changes require a new version and a migration path.

## Reserved field policy

Reserved fields are set to zero by the sender and ignored by the receiver.
They may be repurposed in future versions without a version bump, as long as
the total size of the structure remains the same.
