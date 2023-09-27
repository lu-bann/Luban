// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

// import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";

struct Payment {
    uint256 timestamp;
    uint256 assetAmount;
    uint256 id;
    uint256 chainId;
    address asset;
    address to;
}

struct PaymasterAndData {
    address paymaster;
    address owner;
    uint256 chainId;
    address asset;
    uint256 amount;
}

struct PaymasterAndData2 {
    address paymaster;
    address owner;
    uint256 chainId;
    address paymentAsset;
    uint256 paymentAmount;
    address transferAsset;
    uint256 transferAmount;
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

interface ITestEscrow {

    function interchainSecurityModule() external view returns(address);
    function getBalance(address account_, address asset_) external returns(uint256);
    function getDeadline(address account_) external returns(uint256);
    function getNonce(address account_) external view returns(uint256);
    function getPayment(address account_, uint256 nonce_) external view returns(Payment memory);
    function addEntryPoint(uint256 chainId_, address entryPoint_) external;
    function addCCIPAddress(address ccip, bool state) external;
    function addHyperlaneAddress(address hyperlane, bool state) external;
    function calldataKeccak(bytes calldata data) external pure returns(bytes32);
    function depositAndLock(address account_,  address asset_,  uint256 amount_,  uint256 seconds_,  bytes memory signature_) external;
    function deposit(address account_, address asset_, uint256 amount_) external payable;
    function extendLock(address account_, uint256 seconds_, bytes memory signature_) external;
    function hashSeconds(address account_, uint256 seconds_) external view returns(bytes32);
    function withdraw(address account_, address asset_, uint256 amount_) external;
    function handle(uint32 origin_, bytes32 sender_, bytes calldata message) external;
    // function handleMessage(Client.Any2EVMMessage memory message) external payable;
    // function printOp(Client.Any2EVMMessage memory message) external payable;
    // function callPrintOp(Client.Any2EVMMessage memory message) external payable;

    error WithdrawRejected(string);
    error TransferFailed();
    error InsufficentFunds(address account, address asset, uint256 amount);
    error PaymasterPaymentFailed(address receiver, address asset, address account, uint256 amount);
    error InvalidCCIPAddress(address badSender);
    error InvalidLayerZeroAddress(address badSender);
    error InvalidHyperlaneAddress(address badSender);
    error InvalidChain(uint256 badDestination);
    error InvalidOwner(address owner);
    error InvalidPaymaster(address paymaster);
    error InvalidSignature(address owner, address notOwner);
    error InvalidTimeInput();
    error InvalidDeltaValue();
    error InvalidDeadline(string);
    error BadSignature();
    error BalanceError(uint256 requested, uint256 actual);

    event PrintUserOp(UserOperation userOp, PaymasterAndData paymasterAndData);
}
