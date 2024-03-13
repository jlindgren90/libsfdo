# libsfdo

A collection of libraries which implement [Freedesktop.org specifications].

See respective header files for documentation.

Discuss in [#eclairs on Libera.Chat].

[Freedesktop.org specifications]: https://specifications.freedesktop.org/
[#eclairs on Libera.Chat]: https://web.libera.chat/#eclairs

## Status

Specifications not listed below are out of libsfdo's scope. Specifications marked as N/A are yet to be evaluated as to whether they need to be implemented by libsfdo.

Specification | Library
-|-
autostart-spec | N/A
basedir-spec | `libsfdo-basedir`
desktop-entry-spec | **TODO**
icon-theme-spec | `libsfdo-icon`
mime-apps-spec | N/A
menu-spec | N/A
recent-file-spec | N/A
shared-mime-info-spec | N/A
sound-theme-spec | **TODO**
thumbnail-spec | N/A
trash-spec | **TODO**

## Building

```sh
meson setup build/
ninja -C build/
```

## License

BSD-2-Clause

See `LICENSE` for more information.
