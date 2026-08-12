// SPDX-License-Identifier: MIT
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
