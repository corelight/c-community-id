# c-community-id

This repo provides `communityid.c`, a self-contained, reusable C implementation
of the Community ID standard.

## Usage

To use this implementation in your own codebase, do the following:

* Since applications are likely to implement Community ID support in a
  single complation unit, simply drop `communityid.c` into your surrounding
  C code.
* To abstract low-level implementation details, `communityid.c` assumes
  you have [GLib](https://developer.gnome.org/glib/stable/) and
  [Libgcrypt](https://gnupg.org/software/libgcrypt/index.html) available.
  Modifications to accommodate other low-level data types, hash implementations,
  etc will be straightforward.
* There's a single function, `communityid_calc()` that implements the
  computation. Please take a look at its comments for details regarding
  arguments and return values.

## Example

For a quick usage example, take a look at the included `example.c`, which
implements a command-line tool for computing ID values. If your system
supports `pkg-config` and has GLib and Libgcrypt with development
components installed, the (very basic) included Makefile should work.
A few examples:

```
$ ./example tcp 128.232.110.120 66.35.250.204 34855 80
1:LQU9qZlK+B5F3KDmev6m5PMibrg=
```

See `./example --help` for more details.

## Discussion

Please feel free to report issues or submit PRs via GitHub:
https://github.com/corelight/c-community-id/issues

Contact: Christian Kreibich <christian@corelight.com>
