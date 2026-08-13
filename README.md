# verifyoor

Verify a Solidity smart contract from **EVM runtime bytecode alone** — reconstruct
source + compiler settings that recompile to byte-identical bytecode, to the
**Etherscan/Sourcify partial-match standard** (every byte matches after stripping
the trailing CBOR metadata, which encodes a hash of the original source file and
is unrecoverable from bytecode).

## How it works

Two layers:

1. **Deterministic toolkit** (`verifyoor …`) — all the mechanical work: CBOR
   metadata parsing, disassembly, dispatcher/selector analysis (with body-offset
   tracing), openchain signature resolution (rehash-verified), heimdall
   decompilation, pinned-solc compilation with a settings sweep, masked byte-exact
   comparison, and an **offset-stable normalized-disassembly diff** that attributes
   each remaining divergence to a specific function.
2. **Claude Code skill** (`.claude/skills/verify/SKILL.md`, invoke as `/verify
   <network> <address>`) — Claude is the reconstruction engine, authoring the
   Solidity and refining it against the toolkit's diff feedback in an
   author→compile→diff loop until the toolkit reports a match.

The loop converges because solc is deterministic and its codegen maps source
structure to bytecode directly; the normalized diff makes each iteration's "what
still differs" legible even when a one-line change shifts every jump target.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (manages the Python environment).
- [foundry](https://getfoundry.sh) (`cast`) and [heimdall](https://heimdall.rs) on `PATH`.
- solc binaries under `~/.svm/<version>/solc-<version>` (or `solc-select`) for the
  versions you target; `verifyoor` auto-installs a missing one via `solc-select` when possible.

## Setup

```sh
uv sync          # create the .venv and install deps (pytest, pycryptodome)
```

Everything then runs through `uv run` (no manual venv activation needed). The
one Python dependency is a keccak-256 backend (`pycryptodome`) — Python's stdlib
ships NIST SHA3, which is not Ethereum's keccak.

## CLI

The bytecode source is `<network> <address>` (fetched via `eth_getCode`) or a
single local hex file / hex string:

```sh
uv run verifyoor analyze   ethereum 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
uv run verifyoor decompile <network> <address> --out D
uv run verifyoor verify    <src.sol> <network> <address> --sweep --out runs/<name>

# local bytecode works in place of <network> <address>:
uv run verifyoor analyze   test.hex
uv run verifyoor verify    test.sol test.hex --sweep
```

`<network>` is an alias (`ethereum`, `base`, `arbitrum`, `optimism`, `polygon`,
`bsc`, `sepolia`, …) or a full RPC URL; `--rpc-url` overrides it, and
`VERIFYOOR_RPC_<NETWORK>` is honored. Fetched code is cached under
`~/.cache/verifyoor/bytecode`.

`verify` exits 0 on match (writing `source.sol`, `settings.json`,
`standard-input.json`, `report.{json,md}` to the run dir), 1 on mismatch (printing
a function-attributed diff for the next iteration).

## Publishing (Etherscan / Sourcify)

On a match, verifyoor writes `standard-input.json` — the solc Standard-JSON-Input
with the evmVersion (and optimizer/viaIR) **embedded**. Use standard-json, not
single-file/flatten: the flatten path lets the verifier default the evmVersion,
which silently fails for any contract built for a non-default target (e.g. a
`paris` build on a `0.8.26` contract whose default is `cancun`).

```sh
uv run verifyoor submit runs/<name> <network> <address> --verifier both
```

Submits that standard-json to Etherscan (`$ETHERSCAN_API_KEY` or `--api-key`)
and/or Sourcify (`--verifier etherscan|sourcify|both`) and polls to completion.
Pass `--constructor-args <hex>` if the contract has a constructor with arguments.

## Match standard

Byte-identical after: stripping trailing CBOR metadata from both sides; masking
immutable value slots (recovered and reported); masking library link placeholders
(recovered); masking embedded child-contract metadata (factory contracts).

## Tests

```sh
uv run python tests/fixtures/generate_fixtures.py   # (re)generate fixtures
uv run pytest                                       # 37 tests
```

The suite covers metadata parsing, the dispatcher walk (EQ/SUB forms, trampoline
body-offset tracing), string extraction across all three solc encodings, the
offset-stable diff, immutable masking, viaIR detection, and end-to-end round-trips
of fixtures exercising structs, mappings, events, custom errors, immutables,
optimizer-on, viaIR, and solc 0.7.6. Compile-dependent tests need the matching
solc binaries; network-dependent name resolution is cached (`--offline` to skip).

## License

MIT — see [LICENSE](LICENSE).
