---
name: verify
description: Verify a deployed contract by reconstructing the exact Solidity source that recompiles to its on-chain runtime bytecode (Etherscan/Sourcify partial-match standard). Use when given a `<network> <address>` (e.g. `ethereum 0xC02a…`) — or local runtime bytecode as a .hex file / 0x-hex string — and asked to recover, verify, or match its source. Drives the verifyoor toolkit in an analyze → decompile → author → compile → diff → iterate loop.
---

# verify — deployed contract → matching Solidity source

## Input

Invoked as `/verify <network> <address>` — the toolkit fetches the deployed
runtime bytecode via `eth_getCode`. `<network>` is an alias (`ethereum`, `base`,
`arbitrum`, `optimism`, `polygon`, `bsc`, `sepolia`, … — or a full RPC URL);
`<address>` is `0x` + 40 hex. A single local `.hex` file / hex string also works
in place of `<network> <address>`. Fetched code is cached, so the repeated
analyze/decompile/verify calls below hit the network only once.

> Note: `eth_getCode` returns the code **at that address**. For a proxy this is
> the proxy's own (usually minimal) runtime code — to recover the logic, pass the
> implementation address.

## Goal

Produce Solidity source + compiler settings whose
compiled `deployedBytecode` is **byte-identical to the input after stripping the
trailing CBOR metadata** (and masking immutables / library links / embedded child
metadata). This is the strongest match achievable from bytecode alone — the
metadata section encodes a hash of the original source file, which cannot be
reconstructed. This is exactly Etherscan/Sourcify "partial verification".

You are the reconstruction engine. A deterministic Python toolkit
(`uv run verifyoor …`, run from the repo root — the skill's base directory)
does everything mechanical — analysis, disassembly, compilation, masked
comparison, and an offset-stable diff. Your job is to **author and refine the
Solidity** based on its structured feedback, looping until it reports a match.

## Why this converges

Solc compilation is deterministic for fixed settings, and **unoptimized** output
maps source structure to bytecode very directly (statement order, storage layout,
require/revert strings, function dispatch all appear literally). So the loop is:
write a candidate, compile, read the *function-attributed* diff of what still
differs, fix exactly that, repeat. The diff is normalized so that a change which
shifts every downstream jump target still shows up as one localized region, not
noise.

## The loop

In the commands below, `<TARGET>` is `<network> <address>` (e.g. `ethereum
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`) or a single local hex file / string.
Add `--rpc-url <url>` to override the endpoint.

### 1. Analyze
```
uv run verifyoor analyze <TARGET>
```
Read the human summary (stderr) and JSON (stdout). Note:
- **solc version** and **evm floor** (from metadata + opcodes) → your pragma and `--solc`.
- **optimizer guess** (`off`/`on`/`unknown`) and **viaIR guess** (`likely`/`unlikely`/`unknown`).
  `viaIR: likely` means compile with `--via-ir` from the start — viaIR codegen differs
  substantially from legacy, so guessing wrong wastes the whole loop. (`verify --sweep`
  already tries viaIR first when analyze says likely.)
- **functions**: `selector → signature (resolved & rehash-verified)` with body offsets.
  `UNRESOLVED` means openchain has no verified name — see *Unresolved selectors* below.
- **receive()/fallback()** presence → add `receive() external payable {}` / a `fallback`.
- **strings**: revert/require/log literals — reuse these **verbatim**. Recovered
  across all three solc encodings (shift-encoded `PUSHn X PUSH1 s SHL`, PUSH32
  zero-padded, and long CODECOPY'd data-section literals), so a `strings: []` next
  to visible `Error(string)` reverts (`08c379a0`) means the messages really are
  custom errors, not string literals.
- **resolved_events / resolved_errors**: declare these with the exact signatures.

### 2. Decompile (scaffold)
```
uv run verifyoor decompile <TARGET> --out runs/<name>/heimdall
```
heimdall's output is **approximate pseudocode** — never compiles as-is and often
gets storage math, masks, and control flow wrong. Use it only to see the shape:
state variables, function bodies, rough logic. Trust `analyze` over it for names.

### 3. Author the candidate
Write `runs/<name>/candidate.sol`:
- `pragma solidity <exact metadata version>;` (e.g. `0.8.20`).
- One clean, idiomatic contract. **Function names + parameter types must keccak
  to the observed selectors** — use the resolved signatures directly; a wrong
  name breaks the dispatcher bytes.
- Reuse extracted string literals **exactly** (byte-for-byte).
- Declare resolved events/custom errors with their exact signatures.
- Match visibility/mutability implied by the ABI (`public`/`external`, `view`,
  `payable`). `public` state variables generate getters — use them to satisfy a
  getter selector instead of writing one by hand.

### 4. Verify (compile + compare + diff)
```
uv run verifyoor verify runs/<name>/candidate.sol <TARGET> --sweep --out runs/<name>
```
- `--sweep` searches optimizer (off→on with common runs), evmVersion, and viaIR,
  short-circuiting on the first exact match. Drop `--sweep` (optionally add
  `--optimizer off|on:200`, `--evm shanghai`, `--via-ir`, `--solc X`) to pin
  settings while you iterate on source — it's much faster per call.
- Exit **0 = match** (artifacts written to `runs/<name>/`), **1 = mismatch**.

### 5. Read the diff and fix exactly what differs
On mismatch the JSON lists divergent **regions**, each attributed to a function
with `expected` (on-chain / correct) vs `got` (your candidate) opcode tokens.
Decode `PUSH32 0x…` hex to ASCII to read string literals. Interpretation guide:

| Diff signal | Likely cause → fix |
|---|---|
| `PUSH32`/`PUSH…` data differs in a require/log region | Wrong string literal — copy the expected bytes decoded to ASCII. |
| `PUSH1 0x13` vs `0x12` near a string | String **length** differs — literal length wrong. |
| Extra/missing `ISZERO`+`PUSHDEST`+`JUMPI` block | A `require`/`if` guard is missing or extra. Check zero-address checks, bounds. |
| `expected` has `62461bcd60e51b` shift vs your `PUSH32 08c379a0…` | Optimizer mismatch — re-run with `--sweep` (or `--optimizer on:200`). |
| Custom-error selector (`PUSH4`) vs `Error(string)` (`08c379a0`) | Source uses `revert CustomError()` not `require(_, "str")` (or vice-versa). |
| Diff in SLOAD/SSTORE + slot constants | Storage variable **order/packing** wrong — reorder declarations, fix types. |
| `expected: PUSH32 0x00…00<addr> … AND` vs your `PUSH20 <addr>` | The value is **`immutable`, not `constant`** — declare it immutable and set it in the constructor (on-chain code carries the value; `compare` masks/recovers the slots). |
| Prologue `CALLDATASIZE LT ISZERO …` (expected) vs `CALLDATASIZE LT …` (got) | Target is **viaIR**, your build is legacy — add `--via-ir`. |
| External calls each generate their own inline returndata handling, but the target routes them all through one shared helper (`… JUMP` to a common JUMPDEST) | Make **every** external call the same low-level shape — `(bool s, bytes memory d) = t.call(abi.encodeWithSelector(...))` / `.staticcall(...)` — so solc shares one encode/return helper. Mixing high-level `IERC20.x()` calls with `assembly{call}` blocks each other from sharing. |
| A revert string like `"bal"` appears in the target but not in your build | You used a high-level call that auto-reverts (no message) where the original checks a low-level result: `require(success && data.length >= 32, "bal")` before `abi.decode`. |
| Diff localized to one function body | Rewrite only that function; leave the rest. |
| Huge diff across everything, all settings | Wrong optimizer/viaIR (sweep) or wrong contract shape (constructor logic, inheritance flattening). |

Edit `candidate.sol` (save iterations as `candidate_2.sol`, … for debugging) and
return to step 4. The diff shrinks region-by-region as you converge.

### 6. On match
`verify` writes `source.sol`, `settings.json`, `report.{json,md}` to `runs/<name>/`.
Confirm and summarize for the user:
- match type (partial), solc version + settings that matched, contract name;
- any **recovered immutables** (offset → value) and **library addresses**;
- any **unresolved selectors** whose names are best-effort.

## Unresolved selectors

The function name must keccak to the selector or the dispatcher bytes won't match.
If `analyze` shows `UNRESOLVED`:
1. Infer a plausible name from the decompiled body and parameter types, write it,
   and verify — a wrong guess shows as a dispatcher-region diff (the `PUSH4
   <selector>` comparison), so you'll know immediately.
2. Common patterns: getters mirror state var names; proxy/ERC standards
   (`implementation()`, `owner()`, `balanceOf(address)`).
3. If unrecoverable, name it `func_<selector>` and note in the report that its
   name is unverified — every *resolved* function can still match exactly.

## Stop-loss

If after ~10 iterations the diff isn't converging (regions not shrinking, or
oscillating), stop and report honestly: the closest settings, remaining divergent
regions with their function attributions, and your hypothesis (e.g. viaIR,
unknown optimizer runs, an unresolved selector, or inheritance/library structure
that changes codegen). A precise partial result beats a fabricated "match".

## Notes
- Run all commands from the repo root (the skill's base directory); `uv sync` once first.
- Bytecode is fetched once via `eth_getCode` and cached in
  `~/.cache/verifyoor/bytecode`; `--no-cache` forces a refetch, `--rpc-url`
  overrides the endpoint. Unknown network alias → the error lists valid ones.
- `analyze`/`verify` also hit openchain for name resolution (cached in
  `~/.cache/verifyoor`); add `--offline` to skip that lookup once names are cached.
- Metadata with no solc version (old contracts or stripped builds): pass `--solc`
  yourself, sweeping versions newest→oldest guided by the `evm floor` /
  `solc floor` in `analyze`.
