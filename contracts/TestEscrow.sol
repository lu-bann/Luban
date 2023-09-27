// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {UserOperation, UserOperationLib} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {Strings} from "lib/openzeppelin-contracts/contracts/utils/Strings.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Payment, PaymasterAndData, PaymasterAndData2, ITestEscrow} from "./interfaces/ITestEscrow.sol";

contract TestEscrow is Ownable, ITestEscrow {
    using UserOperationLib for UserOperation;
    using Strings for uint256;
    using ECDSA for bytes32;

    mapping(address => Escrow) _accountInfo;
    mapping(uint256 => address) _entryPoint;
    mapping(address => bool) ccipAddress;
    mapping(address => bool) layerZeroAddress;
    mapping(address => bool) hyperlaneAddress;
    mapping(address => uint256) _escrowBalance;

    address public interchainSecurityModule;

    struct Escrow {
        uint256 deadline;
        uint256 nonce;
        mapping(uint256 => Payment) history;
        mapping(address => uint256) assetBalance;
    }

    bool lock;
    modifier locked() {
        require(!lock, "no reentry");
        lock = true;
        _;
        lock = false;
    }

    function getBalance(address account_, address asset_) public returns(uint256) {
        return _accountInfo[account_].assetBalance[asset_];
    }

    function getDeadline(address account_) public returns(uint256) {
        return _accountInfo[account_].deadline;
    }

    function getNonce(address account_) public view returns(uint256) {
        return _accountInfo[account_].nonce;
    }

    function getPayment(address account_, uint256 nonce_) public view override returns(Payment memory) {
        return _accountInfo[account_].history[nonce_];
    }

    function addEntryPoint(uint256 chainId_, address entryPoint_) public override onlyOwner {
        _entryPoint[chainId_] = entryPoint_;
    }

    function addCCIPAddress(address ccip, bool state) public override onlyOwner {
        ccipAddress[ccip] = state;
    } // supposedly we want to have one escrow for multiple oracle senders

    function addHyperlaneAddress(address hyperlane, bool state) public override onlyOwner {
        hyperlaneAddress[hyperlane] = state;
    }

    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = userOp.preVerificationGas;
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender, nonce,
            hashInitCode, hashCallData,
            callGasLimit, verificationGasLimit, preVerificationGas,
            maxFeePerGas, maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function hash(UserOperation calldata userOp) public pure returns (bytes32) {
        return keccak256(pack(userOp));
    }

    function calldataKeccak(bytes calldata data) override public pure returns (bytes32 ret) {
        assembly {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }

    function getSender(UserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {data := calldataload(userOp)}
        return address(uint160(data));
    }

    /// @dev Deposit and lock in a single contract call
    function depositAndLock(
        address account_, 
        address asset_, 
        uint256 amount_, 
        uint256 seconds_, 
        bytes memory signature_
    ) public {
        deposit(account_, asset_, amount_);
        extendLock(account_, seconds_, signature_);
    }

    // extend lock by calling with value: 0, 0, 0
    /// @dev This function adds funds of amount_ of an asset_, then calls
    ///      _deposit to commit the added funds.
    function deposit(address account_, address asset_, uint256 amount_) public payable locked {
        if(asset_ != address(0)) {
            require(msg.value == 0, "non-payable when using tokens");
            bytes memory payload_ = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", 
                msg.sender, 
                address(this), 
                amount_
            );
            assembly {
                pop(call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0,0))
            }
        }

        _deposit(account_, asset_);
        // need to increment time deposit is locked
    }
    
    /// @dev This function traces the delta of unaccounted changes to the
    ///      escrow balances and then adds that difference to the balance of 
    ///      the owner account.
    function _deposit(address account_, address asset_) internal {
        bytes4 selector_ = bytes4(keccak256("balanceOf(address)"));
        bytes memory payload_ = abi.encodePacked(selector_, account_);
        uint256 escrowBalance_ = _escrowBalance[asset_];
        uint256 delta;
        if(asset_ == address(0)) {
            delta = address(this).balance - escrowBalance_;
        } else {
            assembly {
                pop(call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0, 0x20))
                returndatacopy(0, 0, 0x20)
                delta := sub(mload(0), escrowBalance_)
            }
        }

        if(delta == 0) {
            revert InvalidDeltaValue();
        }

        _accountInfo[account_].assetBalance[asset_] = _accountInfo[account_].assetBalance[asset_] + delta;
    }

    /// @dev The ability to increment lock time must be exclusive to the account owner.
    ///      This is crypographically secured.
    function extendLock(address account_, uint256 seconds_, bytes memory signature_) public {
        if(account_ == address(0)) {
            revert InvalidOwner(account_);
        }

        if(_accountInfo[account_].deadline >= block.timestamp + seconds_) {
            revert InvalidTimeInput();
        }

        bytes32 hash_ = hashSeconds(account_, seconds_);
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash_.toEthSignedMessageHash(), signature_);
        if (error != ECDSA.RecoverError.NoError) {
            revert BadSignature();
        }

        if(recovered != account_) {
            revert InvalidSignature(account_, recovered);
        }

        _accountInfo[account_].deadline = block.timestamp + seconds_;
    }

    // hash is not yet sybil resistent
    function hashSeconds(address account_, uint256 seconds_) override public view returns(bytes32) {
        return keccak256(abi.encode(account_, seconds_));
    }

    function withdraw(address account_, address asset_, uint256 amount_) public locked {
        Escrow storage accountInfo_ = _accountInfo[account_];
        if(accountInfo_.deadline > block.timestamp) {
            revert WithdrawRejected("Too early");
        }

        bool success;
        if(asset_ == address(0)) {
            (success,) = payable(account_).call{value: amount_}("");
        } else {
            bytes memory payload_ = abi.encodeWithSignature("transferFrom(address,address,uint256)", address(this), account_, amount_);
            assembly {
                success := call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0,0)
            }
            
        }

        if(!success) {
            revert TransferFailed();
        }

        if(accountInfo_.assetBalance[asset_] < amount_) {
            revert WithdrawRejected("Insufficent balance");
        }

        accountInfo_.assetBalance[asset_] = accountInfo_.assetBalance[asset_] - amount_;

    }

    function decodePaymasterAndData(bytes calldata message) public view returns(PaymasterAndData memory) {
        address paymaster_ = address(bytes20(message[:20]));
        address owner_ = address(bytes20(message[20:40]));
        uint32 chainId_ = uint32(uint256(bytes32(message[40:72])));
        address paymentAsset_ = address(bytes20(message[72:92]));
        uint256 paymentAmount_ = uint256(bytes32(message[92:124]));
        return PaymasterAndData(paymaster_, owner_, chainId_, paymentAsset_, paymentAmount_);
    }

    function handle(
        uint32 _origin,
        bytes32 _sender,
        bytes calldata message
        ) external {

        if(!hyperlaneAddress[msg.sender]) {
            revert InvalidHyperlaneAddress(msg.sender);
        }

        // // deserialize userop and paymasterAndData
        (UserOperation memory mUserOp, address receiver_) = abi.decode(message, (UserOperation, address));
        PaymasterAndData memory paymasterAndData_ = this.decodePaymasterAndData(mUserOp.paymasterAndData);

        // hash userop locally
        bytes memory payload_ = abi.encodeWithSelector(bytes4(0x7b1d0da3), mUserOp);
        bytes32 userOpHash;
        assembly {
            pop(call(gas(), address(), 0, add(payload_, 0x20), mload(payload_), 0, 0x20))
            userOpHash := mload(0)
        }
        userOpHash = keccak256(abi.encode(
            userOpHash, 
            _entryPoint[paymasterAndData_.chainId], 
            uint256(paymasterAndData_.chainId)
        ));
        
        // validate signature
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(userOpHash.toEthSignedMessageHash(), mUserOp.signature);
        if (error != ECDSA.RecoverError.NoError) {
            revert BadSignature();
        } else {
            if(recovered != paymasterAndData_.owner) {
                revert InvalidSignature(paymasterAndData_.owner, recovered);
            }
        }

        if(paymasterAndData_.paymaster == address(0)) { revert InvalidPaymaster(paymasterAndData_.paymaster); }
        if(paymasterAndData_.chainId == uint256(0)) { revert InvalidChain(paymasterAndData_.chainId); }
        if(paymasterAndData_.owner == address(0)) { revert InvalidOwner(paymasterAndData_.owner); }
        if(paymasterAndData_.owner == address(this)) { revert InvalidOwner(paymasterAndData_.owner); }

        Escrow storage accountInfo_ = _accountInfo[paymasterAndData_.owner];
        if(block.timestamp > accountInfo_.deadline) { revert InvalidDeadline(""); }

        // Transfer amount of asset to receiver
        bool success_;
        address asset_ = paymasterAndData_.asset;
        if(accountInfo_.assetBalance[asset_] < paymasterAndData_.amount) { 
            revert InsufficentFunds(paymasterAndData_.owner, asset_, paymasterAndData_.amount);
        }

        if(asset_ == address(0)) { // address(0) == ETH
            (success_,) = payable(receiver_).call{value: paymasterAndData_.amount}("");
        } else {
            // insufficent address(this) balance will auto-revert
            payload_ = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", 
                address(this), 
                receiver_, 
                paymasterAndData_.amount
            );
            assembly {
                success_ := call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0, 0)
            }
        }
        if(!success_) { 
            revert PaymasterPaymentFailed(
                receiver_, 
                asset_, 
                paymasterAndData_.owner, 
                paymasterAndData_.amount
            );
        }
        accountInfo_.history[accountInfo_.nonce] = Payment(
            block.timestamp,
            paymasterAndData_.amount,
            uint256(0),
            paymasterAndData_.chainId,
            asset_,
            receiver_
        );
        accountInfo_.nonce++;

        uint256 escrowBalance_;
        
        if(asset_ == address(0)) {
            escrowBalance_ = address(this).balance;
        } else {
            payload_ = abi.encodeWithSignature("balanceOf(address)", address(this));
            assembly {
                pop(call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0, 0x20))
                returndatacopy(0, 0, 0x20)
                escrowBalance_ := mload(0)
            }
        }

        _escrowBalance[asset_] = escrowBalance_;

        emit PrintUserOp(mUserOp, paymasterAndData_);
    }

    event PrintUserOp(UserOperation userOp, PaymasterAndData paymasterAndData);

    fallback() external payable {}
}
