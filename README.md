# Dynamic Sizer

A simple cross-platform utility that changes its own executable file size. Written in Rust.

## What it does

The program modifies its own executable file to be whatever size you want. It works by copying itself, resizing the copy, and then swapping the files after exit using a batch script.

## Usage

Run the executable and it will prompt you for a target size:

```
enter target size in b, kb, mb, gb (e.g. 10mb)
requested size:
```

Enter a size like `10mb`, `500kb`, `2gb`. The program exits and a background script swaps the file after.

## Platforms

- **Windows**: Uses batch script (.bat) for file swapping
- **Linux**: Uses shell script (.sh) for file swapping, supports both x86_64 and ARM64 architectures

## Limitations

- **Windows: Maximum size ~4GB** - Windows has a hard limit on PE executable file size. See [this article](https://community.flexera.com/s/article/windows-limit-on-single-compressed-setup-exe) for details.
- **Linux: Maximum size depends on filesystem** - Most modern filesystems support very large files.
- **Large files are slow** - Files over 1GB take longer to start. On Windows, files over 4GB - 1 byte will not run at all.
- Minimum size is the actual compiled executable size (can't be smaller than the real program itself).

## How it works

1. Reads the PE header (Windows) or ELF header (Linux) to find the actual executable size (ignoring any padding)
2. Creates a temporary copy with the new size using `set_len()`
3. Spawns a platform-specific script that waits for the program to exit, then swaps the files

The script tries for 5 minutes to replace the original file, then cleans up and deletes itself.

## Notes

- The program uses standard Rust file operations
- Works on Windows and Linux
- Does not modify PE/ELF headers when enlarging files
- The program can shrink itself back down to minimum size from a larger size
