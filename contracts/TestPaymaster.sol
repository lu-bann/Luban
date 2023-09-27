// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {UserOperation} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {BasePaymaster} from "lib/account-abstraction/contracts/core/BasePaymaster.sol";
import {EntryPoint, IEntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {Client, IRouterClient} from "lib/ccip-starter-kit-foundry/src/BasicMessageSender.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";

interface IMailbox {
    function dispatch( uint32 _destinationDomain, bytes32 _recipientAddress, bytes calldata _messageBody) external returns (bytes32);
}

interface IIGP {
    function payForGas(
        bytes32 _messageId,
        uint32 _destinationDomain,
        uint256 _gasAmount,
        address _refundAddress
    ) external payable;

    function quoteGasPayment(uint32 _destinationDomain, uint256 _gasAmount)
        external
        view
        returns (uint256);
}

// needs to recieve a message from ccip (UserOp, PaymasterAddress)
// then release locked funds
// deserialize PaymasterAndData (paymaster, chainid, target, owner, amount)
//bytes20, bytes8, bytes20, bytes20, bytes32 = 100 bytes
// chainid == block.chainid
// validateSignature == owner
// transfer amount to paymaster 
contract TestPaymaster is BasePaymaster {
    mapping(uint256 => address) public escrowAddress;
    mapping(uint256 => bool) public acceptedChain; // destinationDomain
    mapping(uint256 => mapping(address => bool)) public acceptedAsset;
    mapping(address => bool) public acceptedOrigin;
    
    bytes4 _selector;
    address hyperlane_mailbox;
    address hyperlane_igp;
    address defaultReceiver;

    // later version this will be packed instead
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

    constructor(
        IEntryPoint entryPoint_, 
        address hyperlane_mailbox_, 
        address hyperlane_igp_,
        address defaultReceiver_
        ) BasePaymaster(entryPoint_) {
        _selector = bytes4(keccak256("HandleMessage(bytes)"));
        hyperlane_mailbox = hyperlane_mailbox_;
        hyperlane_igp = hyperlane_igp_;
        defaultReceiver = defaultReceiver_;
    }

    function getEscrowAddress(uint256 chainId) public view returns(address) {
        return escrowAddress[chainId];
    }

    function addEscrow(uint256 chainId, address escrowAddress_) public onlyOwner {
        escrowAddress[chainId] = escrowAddress_;
    }

    function addAcceptedChain(uint256 chainId_, bool state_) public onlyOwner {
        acceptedChain[chainId_] = state_;
    }

    function addAcceptedAsset(uint256 chainId_, address asset_, bool state_) public onlyOwner {
        acceptedAsset[chainId_][asset_] = state_;
    }

    function addAcceptedOrigin(address origin_, bool state_) public onlyOwner {
        acceptedOrigin[origin_] = state_;
    }

    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 requiredPreFund)
    internal
    override
    returns (bytes memory context, uint256 validationResult) {unchecked {
        // if(!acceptedOrigin[tx.origin]) {
        //     revert InvalidOrigin(tx.origin);
        // } // will be using at some later point 

        //requiredPreFund is already subtracted from stake

        // send with hash and signature
        bytes calldata data = userOp.paymasterAndData;

        uint256 paymasterAndDataLength = data.length;
        // 124 == crosschain non-payable
        if(paymasterAndDataLength != 124 && paymasterAndDataLength != 176) {
            revert InvalidDataLength(paymasterAndDataLength);
        }

        // non-payable
        address paymaster_ = address(bytes20(data[:20]));
        address owner_ = address(bytes20(data[20:40]));
        uint256 chainId_ = uint256(bytes32(data[40:72]));
        address paymentAsset_ = address(bytes20(data[72:92]));
        uint256 paymentAmount_ = uint256(bytes32(data[92:124]));
        // payable: can be anything so long as paymaster has sufficent funds
        // TODO: will enable bridge functionality
        // address transferAsset_ = address(bytes20(data[124:144]));
        // uint256 transferAmount_ = uint256(bytes32(data[144:176]));

        bytes32 messageId_;
        uint256 gasAmount_ = 100000;
        uint32 destinationDomain_ = uint32(chainId_);

        // paymaster must elect to accept funds from specific chains
        if(!acceptedChain[destinationDomain_]) {
            revert InvalidChainId(destinationDomain_);
        }

        if(!acceptedAsset[destinationDomain_][paymentAsset_]) {
            revert InvalidAsset(destinationDomain_, paymentAsset_);
        }

        // for now non-staked deposit is used for the oracle call
        // DepositInfo memory depositInfo_ = entryPoint.deposits(address(this));
        // require(depositInfo_.deposit >= 0.2 ether);
        entryPoint.withdrawTo(payable(address(this)), 0.2 ether);

        address receiver = escrowAddress[destinationDomain_] != address(0) ? escrowAddress[destinationDomain_] : address(this);
        bytes32 recipientAddress_ = bytes32(uint256(uint160(receiver)));
        IMailbox(hyperlane_mailbox).dispatch(destinationDomain_, recipientAddress_, abi.encode(userOp, receiver));
        IIGP(hyperlane_igp).quoteGasPayment(destinationDomain_, gasAmount_);
        context = abi.encode(messageId_, destinationDomain_, gasAmount_);
    }}

    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        //we don't really care about the mode, we just pay the gas with the user's tokens.
        (mode);
        bytes32 messageId_;
        uint32 destinationDomain_;
        uint256 gasAmount_;
        address refundAddress_;
        (messageId_, destinationDomain_, gasAmount_) = abi.decode(context, (bytes32, uint32, uint256));
        IIGP(hyperlane_igp).payForGas{value: address(this).balance}(
            messageId_,
            destinationDomain_,
            gasAmount_,
            address(this) // refundAddress_
        );
    }

    receive() external payable {
        if(msg.value != 0 && msg.sender == hyperlane_igp) {
            entryPoint.depositTo(address(this));
        }
    }

    fallback() external payable {}

    error InvalidChainId(uint32 chainId);
    error InvalidOrigin(address bundler);
    error InvalidAsset(uint32 chainId, address asset);
    error InvalidDataLength(uint256 dataLength);
}
