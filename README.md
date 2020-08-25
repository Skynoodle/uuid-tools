# UUID Tools

This package is intended as a set of simple, useful command-line tooling for
generating and inspecting UUIDs. It is currently very much a toy project,
and _should not_ be relied upon for any critical uuid generation - it lacks
proper support for generating any but Nil and v4 Random UUIDs.

The package provides a single binary crate, `uuid`, which accepts an optional
argument specifying a uuid to decode and provide details. If absent, `uuid`
will instead generate a uuid, defaulting to v4 random.

Any successful invocation of `uuid` will cause either the parsed or generated
uuid to be printed to `stdout` in the format requested, while all additional
information is listed on `stderr` for convenient use in command pipelines.
