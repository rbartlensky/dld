## dld -- The dummy linker

A very WIP linker.

### Try it out

```
$ cargo build && clang -o test ./tests/c/main.c -fuse-ld=/path/to/dld/target/debug/dld
$ ./test # works
```
