# Adding a new capability

By design, infrascan breaks every unique action into its own top level command. If you are looking to add a brand new capability to the tool, you can take the following steps.

1. Add a file to `cmd/` that corresponds to the sub-command name you'd like to add to the `infrascan` CLI (if you are adding a new `discover` subcommand add to the `cmd/discover.go`, for example)
2. You can use `cmd/discover.go` as a template
3. Your file needs to be a member function of the `infrascan` struct and should be of the form `Init<cmd>Command`
4. Add a new member to the `infrascan` struct in `cmd/root.go` that corresponsds to your command name. Remember, the first letter must be capitalized.
5. Call your `Init` function from `main.go`
6. Add logic to your commands runtime and put it in its own package within `internal` (e.g., `internal/discover/waps`)
