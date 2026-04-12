// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract SimpleVault {
    address public owner;
    address public feeRecipient;
    address public implementation;
    bool public paused;
    uint256 public feeBalance;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner only");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(address initialFeeRecipient) payable {
        owner = msg.sender;
        feeRecipient = initialFeeRecipient;
    }

    function deposit() external payable whenNotPaused {
        uint256 fee = msg.value / 100;
        uint256 principal = msg.value - fee;
        balances[msg.sender] += principal;
        feeBalance += fee;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function withdrawFees(uint256 amount) external onlyOwner {
        require(amount <= feeBalance, "fee balance");
        feeBalance -= amount;
        (bool ok,) = payable(feeRecipient).call{value: amount}("");
        require(ok, "fee transfer failed");
    }

    function setFeeRecipient(address newFeeRecipient) external onlyOwner {
        feeRecipient = newFeeRecipient;
    }

    function upgradeTo(address newImplementation) external onlyOwner {
        implementation = newImplementation;
    }

    receive() external payable {
        feeBalance += msg.value;
    }
}
