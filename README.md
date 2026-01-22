# NullSec APIMon

OCaml API call monitor demonstrating functional programming and strong static typing.

## Features

- **Algebraic Data Types** - Type-safe API representations
- **Pattern Matching** - Exhaustive case analysis
- **Immutable Structures** - Thread-safe by default
- **Module System** - Clean code organization
- **Rule Engine** - Configurable detection rules

## Detections

| Rule ID | Category | Severity | API Pattern |
|---------|----------|----------|-------------|
| INJ001-004 | Injection | Critical | VirtualAllocEx, WriteProcessMemory |
| CRED001-003 | Credential | Critical/High | CredEnumerate, LsaRetrievePrivateData |
| ANTI001-002 | Anti-Analysis | High/Medium | IsDebuggerPresent, CPUID |
| FILE001-002 | File System | Medium/High | DeleteFile, vssadmin |
| REG001-002 | Registry | Medium | RegSetValue, RegDeleteKey |

## Build

```bash
# With OCaml compiler
ocamlfind ocamlopt -package unix -linkpkg apimon.ml -o apimon

# With Dune (create dune file first)
dune build

# Bytecode
ocamlfind ocamlc -package unix -linkpkg apimon.ml -o apimon
```

## Usage

```bash
# Monitor process
./apimon 1234

# Show all calls
./apimon -a 1234

# Filter by category
./apimon -c Network 1234

# JSON output
./apimon -j 1234 > trace.json
```

## Categories

- FileSystem - File operations
- Registry - Registry access
- Network - Socket/connection
- Process - Process manipulation
- Memory - Memory operations
- Crypto - Cryptographic APIs
- System - System calls

## Author

bad-antics | [Discord](https://discord.gg/killers)

## License

MIT
