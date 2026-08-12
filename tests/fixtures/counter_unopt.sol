// SPDX-License-Identifier: MIT
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
