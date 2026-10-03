# Fork Notice

This is a modified fork of [BlackSnufkin/Maverick](https://github.com/BlackSnufkin/Maverick).

- **Original author:** BlackSnufkin
- **Original license:** GNU GPL v3 (see LICENSE)
- **Forked:** 2026-10-03
- **Fork author:** [wzaremba2005-pixel](https://github.com/wzaremba2005-pixel)

## Changes

- Fixed 18 bugs across C agent, loaders, and headers
- Verified C ↔ Go wire protocol bit-exactly
- End-to-end tested on Windows 11 + Adaptix v1.2
- Hardened Ekko sleep mask (memory leak fix, random RC4 key)
- Fixed DEP bypass in loaders (`RunShellcode`)

All modifications remain under GPL v3.
