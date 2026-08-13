pragma solidity 0.8.20;

contract Test {

    address public destination;

    function initialize(address _addr) public {
        require(_addr != address(0), 'Invalid destination');
        destination = _addr;
    }

    receive() external payable {
        require(destination != address(0), 'Not initialized');
        payable(destination).transfer(msg.value);
    }
}