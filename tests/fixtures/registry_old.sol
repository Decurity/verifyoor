// SPDX-License-Identifier: MIT
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
