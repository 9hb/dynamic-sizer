# Dynamic Sizer

A simple Windows utility that changes its own executable file size. Written in Rust.

## What it does

The program modifies its own .exe file to be whatever size you want. It works by copying itself, resizing the copy, and then swapping the files after exit using a batch script.

## Usage

Run the executable and it will prompt you for a target size:

```
enter target size in b, kb, mb, gb (e.g. 10mb)
requested size:
```

Enter a size like `10mb`, `500kb`, `2gb`. The program exits and a background script swaps the file after.

## Limitations

- **Maximum size: ~4GB** - Windows has a hard limit on PE executable file size. See [this article](https://community.flexera.com/s/article/windows-limit-on-single-compressed-setup-exe) for details.
- **Large files are slow** - Files over 1GB take longer to start, but still works. Files over 4GB - 1 byte will not run at all.
- Minimum size is the actual compiled executable size (can't be smaller than the real program itself).

## How it works

1. Reads the PE header to find the actual executable size (ignoring any padding)
2. Creates a temporary copy with the new size using `set_len()`
3. Spawns a batch script that waits for the program to exit, then swaps the files

The batch script tries for 5 minutes to replace the original file, then cleans up and deletes itself.

## Building

```bash
cargo build --release
```

The executable will be in `target/release/dynamic-sizer-rs.exe`.

## Notes

- The program uses standard Rust file operations
- Works only on Windows (uses .bat script for file swapping)
- Does not modify PE headers when enlarging files, so executables larger than mentioned _4GB - 1 byte_ won't run
- The program can shrink itself back down to minimum size from a larger size
