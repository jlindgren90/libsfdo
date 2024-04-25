# libsfdo

A collection of libraries which implement some of [the Freedesktop.org specifications].

See respective header files for documentation (TODO).

Discuss in [#eclairs on Libera.Chat].

[the Freedesktop.org specifications]: https://specifications.freedesktop.org/
[#eclairs on Libera.Chat]: https://web.libera.chat/#eclairs

## Disclaimer

Freedesktop.org specifications are rather poorly written and leave a lot of room for interpretation.
libsfdo tries to follow them as closely as possible nonetheless, except for cases when doing so
would add too much complexity for no benefit and/or result in suboptimal behavior. Additionally,
libsfdo is much stricter than other implementations, so it may refuse to process non-conformant
desktop entry files or icon themes. It is advised that you try to fix the offending files before
opening an issue.

## Implementations

Specification | Library
-|-
basedir-spec | `libsfdo-basedir`
desktop-entry-spec | `libsfdo-desktop`, `libsfdo-desktop-file`
icon-theme-spec | `libsfdo-icon`

## Building

```sh
meson setup build/
ninja -C build/
```

## License

BSD-2-Clause

See `LICENSE` for more information.
