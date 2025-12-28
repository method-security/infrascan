# infrascan Project Context

## Overview

infrascan is an Infrastructure and Wireless signal scanning and enumeration tool that provides security teams with data-rich insights into infrastructure resources and targets. It follows the CLI Development Conventions for attack stage organization and implements discover, enumerate, and pentest capabilities.

## Architecture

The tool follows the standard CLI Development Conventions with clear separation by attack stages:

### Attack Stages

1. **Discover Stage** (`internal/discover/`)
   - Passive reconnaissance and information gathering
   - Target fingerprinting without direct interaction

2. **Enumerate Stage** (`internal/enumerate/`)
   - Deep inspection of discovered targets

3. **Pentest Stage** (`internal/pentest/`)
   - Attack surface mapping

### Core Components

1. **Discovery Module** (`internal/discover/`)
   - Wireless Access Point discovery

2. **Enumeration Module** (`internal/enumerate/`)

3. **Penetration Testing Module** (`internal/pentest/`)

### CLI Structure (`cmd/`)
- `root.go` - Main CLI setup with Cobra
- `discover.go` - Discovery command implementations
- `enumerate.go` - Enumeration command implementations  
- `pentest.go` - Penetration testing command implementations

### Generated Code (`generated/go/`)
- Fern-generated Go types and clients
- Infrascan data definitions and structures
- API interfaces for type safety

## Project Structure

- **Language**: Go
- **Module**: github.com/Method-Security/infrascan
- **CLI Framework**: Cobra
- **Type Generation**: Fern
- **Testing**: Standard Go testing + external API integration tests

## Key Infrascan Capabilities

- **Wireless Access Point**: WAP discovery, and enumeration

## Development Patterns

### CLI Development Conventions
- Follow the CLI Development Conventions for attack stage organization
- Use `<stage>Cmd` in camelCase for top-level commands (e.g., `discoverCmd`)
- Use `<stage><Component>Cmd` for subcommands (e.g., `discoverDomainCmd`)
- Implement Run functions with action verbs (e.g., `RunWAPDiscovery`)

### Flag Naming and Handling
- Use kebab-case for CLI flags: `--target-ssid`
- Use camelCase when extracting flags: `targetSSID, err := cmd.Flags().GetString("target-ssid")`
- Always check errors when extracting flags:
  ```go
  if err != nil {
      a.OutputSignal.AddError(err)
      return
  }
  ```
- Use `.GetStringSlice` for slice inputs with plural flag names
- Mark required flags explicitly: `_ = cmd.MarkFlagRequired("target")`

### Code Organization
- Repository organized by attack stage (`discover`, `enumerate`, `pentest`)
- Mirror naming between `fern/definition/<stage>/<component>.yml`, `internal/<stage>/<component>.go`, and `cmd/<stage>.go`
- Use subdirectories for complex components, flat files for simple ones

### Infrascan-Specific Patterns

### Error Handling
```go
if err != nil {
    a.OutputSignal.AddError(err)
    return
}
```

### Fern Type Requirements
- **MANDATORY**: Every CLI command with output must have a corresponding Fern report structure
- **Three-Part Structure Pattern**: All commands must define:
  ```yaml
  # 1. Config type for input parameters
  <Stage><Component>Config:
    properties:
      # Infrascan-specific configuration parameters
      target: string
  
  # 2. Result type for output data
  <Stage><Component>Result:
    properties:
      # Infrascan-specific result data
      wirelessAccessPoints: optional<list<WAPInfo>>
  
  # 3. Report type wrapping config, result, and errors
  <Stage><Component>Report:
    properties:
      config: <Stage><Component>Config
      result: <Stage><Component>Result
      errors: optional<list<string>>
  ```
- **Infrascan Example Implementation**:
  TODO
  ```yaml
  ```
- **Infrascan-Specific Types**: Include Infrascan-specific enums and objects:
  TODO
  ```yaml
  ```
- **Type Organization**: Follow the CLI Development Conventions type ordering:
  1. ENUMs (e.g., `DataSource`)
  2. Common Objects (e.g., `WAPInfo`)
  3. Config Types (e.g., `DiscoverWAPConfig`)
  4. Result Types (e.g., `DiscoverWAPResult`)
  5. Report Types (e.g., `DiscoverWAPReport`)

### Output Structure
```go
a.OutputSignal.Content = report
```

## Important Notes

TODO

## Development Commands

```bash
# MANDATORY: Run after completing TODOs to ensure code can be merged
./godelw verify

# Build the binary
./godelw build
```

## Development Workflow

1. Follow CLI Development Conventions for new commands
2. Use Fern definitions for type safety
3. Implement proper rate limiting and error handling
4. Test with various target types and scenarios
5. Follow existing patterns for consistency
6. **CRITICAL**: Always run `./godelw verify` after TODO completion before merging

## File Structure Conventions

- `/cmd/` - CLI command implementations
- `/internal/<stage>/` - OSINT capability implementations
- `/fern/definition/` - Fern API definitions
- `/generated/go/` - Generated Go code
- `/configs/` - Configuration files and wordlists
- `/docs/` - Documentation

## Development Practices

- Follow CLI Development Conventions exactly
- Implement comprehensive error handling and rate limiting
- Handle sensitive data appropriately
- Always end files with a single newline