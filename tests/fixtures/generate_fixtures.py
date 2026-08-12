"""Generate harder self-test fixtures: compile contracts with pinned solc, store
only the runtime bytecode hex. The source is kept as an oracle but is NEVER fed
to the tool during agentic reconstruction tests.

Run: python3 tests/fixtures/generate_fixtures.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from verifyoor.compile import Settings, compile_standard  # noqa: E402

# (name, solc_version, Settings, source)
FIXTURES = [
    (
        "vault",
        "0.8.20",
        Settings(optimizer_enabled=True, optimizer_runs=200, evm_version="shanghai"),
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Vault {
    struct Position { uint128 amount; uint64 unlock; address token; }

    address public immutable owner;
    uint256 public immutable createdAt;
    mapping(address => Position) public positions;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalDeposited;

    event Deposited(address indexed user, address indexed token, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    error NotOwner();
    error ZeroAmount();
    error Locked(uint64 unlock);

    constructor(uint256 _createdAt) {
        owner = msg.sender;
        createdAt = _createdAt;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function deposit(address token, uint128 amount, uint64 lockFor) external {
        if (amount == 0) revert ZeroAmount();
        Position storage p = positions[msg.sender];
        p.amount += amount;
        p.unlock = uint64(block.timestamp) + lockFor;
        p.token = token;
        totalDeposited += amount;
        emit Deposited(msg.sender, token, amount);
    }

    function withdraw(uint128 amount) external {
        Position storage p = positions[msg.sender];
        if (block.timestamp < p.unlock) revert Locked(p.unlock);
        require(p.amount >= amount, "insufficient");
        p.amount -= amount;
        totalDeposited -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function sweep() external onlyOwner {
        totalDeposited = 0;
    }
}
""",
    ),
    (
        "counter_unopt",
        "0.8.20",
        Settings(optimizer_enabled=False, evm_version="shanghai"),
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Counter {
    uint256 public count;
    address public last;

    event Bumped(address indexed by, uint256 newCount);

    function increment() public {
        count += 1;
        last = msg.sender;
        emit Bumped(msg.sender, count);
    }

    function add(uint256 n) external {
        require(n > 0, "zero");
        count += n;
    }

    function reset() external {
        count = 0;
    }
}
""",
    ),
    (
        "registry_old",
        "0.7.6",
        Settings(optimizer_enabled=True, optimizer_runs=200, evm_version="istanbul"),
        """// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

contract Registry {
    mapping(bytes32 => address) public records;
    address public admin;

    event Set(bytes32 indexed key, address value);

    constructor() {
        admin = msg.sender;
    }

    function setRecord(bytes32 key, address value) external {
        require(msg.sender == admin, "not admin");
        records[key] = value;
        emit Set(key, value);
    }

    function get(bytes32 key) external view returns (address) {
        return records[key];
    }
}
""",
    ),
    (
        # viaIR build with a receive() and an immutable — exercises the SUB-form
        # last selector, receive detection, and the viaIR heuristic.
        "rescuer_viair",
        "0.8.35",
        Settings(optimizer_enabled=True, optimizer_runs=200, evm_version="shanghai", via_ir=True),
        """// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Rescuer {
    address public immutable deployer;

    constructor() {
        deployer = msg.sender;
    }

    modifier onlyDeployer() {
        require(msg.sender == deployer, "only deployer");
        _;
    }

    receive() external payable {}

    function rescueETH(uint256 amount) external onlyDeployer {
        if (amount == 0) amount = address(this).balance;
        address d = deployer;
        bool ok;
        assembly {
            ok := call(gas(), d, amount, 0, 0, 0, 0)
        }
        require(ok, "eth");
    }

    function rescueToken(address token, uint256 amount) external onlyDeployer {
        if (amount == 0) amount = IERC20(token).balanceOf(address(this));
        require(IERC20(token).transfer(deployer, amount), "transfer");
    }
}
""",
    ),
]


def main() -> int:
    manifest = {}
    for name, version, settings, source in FIXTURES:
        src_path = os.path.join(HERE, name + ".sol")
        with open(src_path, "w") as f:
            f.write(source)
        res = compile_standard(source, version, settings, source_name=name + ".sol")
        if not res.ok:
            print("FAIL %s: %s" % (name, res.errors[:1]))
            return 1
        contract = res.pick()  # single contract per file
        hex_path = os.path.join(HERE, name + ".hex")
        with open(hex_path, "w") as f:
            f.write("0x" + contract.deployed_object)
        manifest[name] = {
            "solc": version,
            "settings": settings.describe(),
            "contract": contract.name,
            "runtime_len": contract.deployed_len,
            "immutables": bool(contract.immutable_refs),
        }
        print("OK %s: %s, %d bytes, %s" % (name, version, contract.deployed_len, settings.describe()))
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
