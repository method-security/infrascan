# Project Principles

## Pre-run -> Run -> Post-run

In the root command, we set a `PersistentPreRunE` and `PersistentPostRunE` function that is responsible for initializing the output format and Signal data (in the pre-run) and then write that data in the proper format (in the post-run).

Within the Run command that every command must implement, the output of the collected data needs to be written back to the struct's `OutputSignal.Content` value in order to be properly written out to the caller.

## Cmd vs Internal

By design, the functionality within each command should focus around parsing the variety of flags and options that the command may need to control capability, passing off all real logic into internal modules.

## Platform-Specific Build Tags

The wireless access point discovery (`discover waps`) uses platform-specific system utilities to enumerate nearby networks. Because these tools and their output formats differ significantly between operating systems, the scanning logic is split into separate files using Go build tags (e.g., `//go:build darwin`). This ensures that only the relevant platform code is compiled into the final binary, keeping the executable lean and avoiding any cross-platform import issues.

The main orchestration code in `waps.go` references all platform-specific scan functions (`scanDarwin`, `scanLinux`, `scanWindows`) in a runtime switch statement. Since Go's compiler requires all referenced functions to be defined at compile time—even if they're unreachable at runtime—we provide stub implementations for the non-target platforms. For example, when compiling on macOS, the `scanLinux` and `scanWindows` stubs return an error indicating they're unavailable. This pattern allows the codebase to compile cleanly on any platform while ensuring users get a clear error message if they somehow invoke the wrong code path.

The same pattern applies to privilege checking functions (`isUnixRoot`, `isWindowsAdmin`) which are implemented differently per platform to check for the elevated privileges required by passive mode.