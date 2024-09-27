// SPDX-License-Identifier: MIT
pragma solidity ^0.8.1;

// Importing necessary OpenZeppelin libraries
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract ERC20CrossChainBridge is Ownable {
    using SafeERC20 for IERC20;
    using Address for address;

    constructor() Ownable(msg.sender) {}

    // Events
    event DepositERC20(address indexed from, address indexed to, uint256 amount, uint256 gasLimit);
    event FinalizeWithdrawERC20(address indexed from, address indexed to, uint256 amount);
    event OwnerWithdrawERC20(address indexed token, address indexed to, uint256 amount);
    event OwnerWithdrawEther(uint256 amount, address indexed to);
    // Core deposit function
    function depositERC20(
        address _token,
        address _to,
        uint256 _amount,
        uint256 _gasLimit
    ) external payable {
        require(_amount > 0, "Deposit amount must be greater than 0");
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        
        // Emit deposit event for off-chain processing
        emit DepositERC20(msg.sender, _to, _amount, _gasLimit);
    }

    // Core withdraw function
    function finalizeWithdrawERC20(
        address _token,
        address _from,
        address _to,
        uint256 _amount
    ) external {
        require(_amount > 0, "Withdraw amount must be greater than 0");
        IERC20(_token).safeTransfer(_to, _amount);

        // Emit withdraw event for off-chain processing
        emit FinalizeWithdrawERC20(_from, _to, _amount);
    }

    function ownerWithdrawERC20(
    address _token,
    uint256 _amount,
    address _to
    ) external onlyOwner {
        require(_amount > 0, "Withdraw amount must be greater than 0");
        require(_to != address(0), "Invalid recipient address");
        IERC20(_token).safeTransfer(_to, _amount);
        emit OwnerWithdrawERC20(_token, _to, _amount);
    }

    function ownerWithdrawEther(uint256 _amount, address payable _to) external onlyOwner {
        require(_amount > 0, "Withdraw amount must be greater than 0");
        require(address(this).balance >= _amount, "Insufficient Ether balance");
        _to.transfer(_amount);
        emit OwnerWithdrawEther(_amount, _to);
    }

    // Fallback function to receive Ether
    receive() external payable {}

    // A simple function to check the contract balance for a token
    function getBalance(address _token) external view returns (uint256) {
        return IERC20(_token).balanceOf(address(this));
    }
}