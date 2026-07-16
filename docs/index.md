# shimcache-forensic

Decode the Windows **AppCompatCache (ShimCache)** from a `SYSTEM` hive — on any OS.

`shimcache-core` is the pure decoder (`parse(&[u8]) -> Vec<ShimcacheEntry>`, Windows XP through 11);
`shimcache-forensic` adds graded findings and the **`shimcache4n6`** CLI.

```console
$ cargo install shimcache-forensic
$ shimcache4n6 /path/to/SYSTEM
```

See the [project README](https://github.com/SecurityRonin/shimcache-forensic) for full usage, the
supported formats, and the findings table, and [Validation](validation.md) for how correctness is
established.
