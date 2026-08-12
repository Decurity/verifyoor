// SPDX-License-Identifier: MIT
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
