# verifyoor

Verify a Solidity smart contract from **EVM runtime bytecode alone** — reconstruct
source + compiler settings that recompile to byte-identical bytecode, to the
**Etherscan/Sourcify partial-match standard** (every byte matches after stripping
the trailing CBOR metadata, which encodes a hash of the original source file and
is unrecoverable from bytecode).

**Demo:** a contract reconstructed and verified with verifyoor —
[`0xbdd0…9516`](https://etherscan.io/address/0xbdd077f651ebe7f7b3ce16fe5f2b025be2969516#code)
(published on Etherscan and Sourcify).

## How it works

Two layers:

1. **Deterministic toolkit** (`verifyoor …`) — all the mechanical work: CBOR
   metadata parsing, disassembly, **evmole**-primary selector / argument-type /
   state-mutability / **storage-layout** extraction with trampoline body-offset
   tracing (a built-in dispatcher walk is the fallback), **Sourcify** 4byte resolution
   (rehash-verified, verified-contract names ranked first),
   an **intra-block IR lift** (per-basic-block symbolic stack execution into
   Yul-style statements — deterministic and complete for EVM bytecode — with
   inter-block edges resolved from **evmole's CFG**, incl. context-sensitive dynamic
   jumps; surfaced standalone via `lift` and inline in every diff region),
   **selector minting** (mint a function name for an exact selector when the real
   name is unrecoverable — a collision or a custom name), pinned-solc compilation
   with a settings sweep, masked byte-exact comparison, and an **offset-stable
   normalized-disassembly diff** that attributes each remaining divergence to a
   specific function via **context-sensitive CFG** analysis (each function's
   context-matched reachable blocks; a divergence in genuinely shared codegen reads
   `shared helper` instead of being misattributed to a neighbor).
2. **Claude Code skill** (`.claude/skills/verify/SKILL.md`, invoke as `/verify
   <network> <address>`) — Claude is the reconstruction engine, authoring the
   Solidity and refining it against the toolkit's diff feedback in an
   author→compile→diff loop until the toolkit reports a match.

The loop converges because solc is deterministic and its codegen maps source
structure to bytecode directly; the normalized diff makes each iteration's "what
still differs" legible even when a one-line change shifts every jump target.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (manages the Python environment).
- [foundry](https://getfoundry.sh) (`cast`) on `PATH`.
- solc binaries under `~/.svm/<version>/solc-<version>` (or `solc-select`) for the
  versions you target; `verifyoor` auto-installs a missing one via `solc-select` when possible.

[evmole](https://github.com/cdump/evmole) is a core Python dependency (installed by
`uv sync`) — it's the primary source for selectors, argument types, and state
mutability in `analyze`. If it errors on a given input, analysis falls back to the
built-in dispatcher walk.

## Setup

```sh
uv sync          # create the .venv and install deps (pytest, pycryptodome, evmole)
```

Everything then runs through `uv run` (no manual venv activation needed). The
one Python dependency is a keccak-256 backend (`pycryptodome`) — Python's stdlib
ships NIST SHA3, which is not Ethereum's keccak.

## CLI

The bytecode source is `<network> <address>` (fetched via `eth_getCode`) or a
single local hex file / hex string:

```sh
uv run verifyoor analyze   ethereum 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
uv run verifyoor lift      <network> <address> --out runs/<name>/lift.txt
uv run verifyoor mine-selector 0x2247831f "(address[],uint256[])"
uv run verifyoor verify    <src.sol> <network> <address> --sweep --out runs/<name>

# local bytecode works in place of <network> <address>:
uv run verifyoor analyze   tests/fixtures/sample.hex
uv run verifyoor verify    tests/fixtures/sample.sol tests/fixtures/sample.hex --sweep
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

## Selector mining

A function's name never appears in runtime bytecode — solc's dispatcher carries
only the 4-byte selector `keccak(name+argtypes)[:4]`. So when a function's real
name is unrecoverable (a custom name absent from signature DBs, or a selector
**collision** where the DB resolves the wrong preimage — e.g. a 2-array batch
function that happens to share `transfer`'s `0xa9059cbb`), you don't need the
name. Take the **arg types** from `analyze` (evmole; they drive the body's codegen
and must be right — cross-check the `lift` IR when in doubt), then mint any name
that hashes to the selector:

```sh
uv run verifyoor mine-selector 0x2247831f "(address[],uint256[])"
# -> func_2247831f_<n>(address[],uint256[])   (selector == 0x2247831f, re-verified)
```

The minted `func_<selector>_<n>` name is cosmetic; only the selector lands in
bytecode, so the compiled runtime is byte-identical. Mining is a ~2³² keccak
search with two backends (auto-selected; every result re-verified with keccak):

- **external** (fast) — [Vectorized's `function-selector-miner`](https://github.com/Vectorized/function-selector-miner)
  (MIT; Rust, AVX2 + multithread), sub-minute on an x86+AVX2 host. Build it
  (`cargo build --release`) and either put `function-selector-miner` on `PATH` or
  point `VERIFYOOR_SELECTOR_MINER` at the binary. On non-AVX2 hosts (e.g. Apple
  Silicon) it falls back to a scalar path, ~on par with the Python backend.
- **python** (fallback) — pure-Python multiprocessing, no build step; always
  present. Force it with `--python`.

## Match standard

Byte-identical after: stripping trailing CBOR metadata from both sides; masking
immutable value slots (recovered and reported); masking library link placeholders
(recovered); masking embedded child-contract metadata (factory contracts).

## Tests

```sh
uv run python tests/fixtures/generate_fixtures.py   # (re)generate fixtures
uv run pytest                                       # 82 tests (2 gate on the external miner)
```

The suite covers metadata parsing, the dispatcher walk (EQ/SUB forms, trampoline
body-offset tracing), string extraction across all three solc encodings, the
offset-stable diff, the intra-block IR lift (stack semantics, let/temp policy,
block splitting) with CFG edge resolution, context-sensitive CFG attribution,
selector minting (both backends), evmole enrichment (arg types, mutability, storage
layout), immutable masking, viaIR detection, and round-trips
of fixtures exercising structs, mappings, events, custom errors, immutables,
optimizer-on, viaIR, and solc 0.7.6. Compile-dependent tests need the matching
solc binaries; network-dependent name resolution is cached (`--offline` to skip).

## License

MIT — see [LICENSE](LICENSE).
