// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {UserOperation, UserOperationLib} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";
import {Strings} from "lib/openzeppelin-contracts/contracts/utils/Strings.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Payment, PaymasterAndData, PaymasterAndData2, ITestEscrow} from "./interfaces/ITestEscrow.sol";

// needs to recieve a message from ccip (UserOp, PaymasterAddress)
// then release locked funds
// deserialize PaymasterAndData (paymaster, chainid, target, owner, amount)
// chainid == block.chainid
// validateSignature == owner
// transfer amount to paymaster 
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

    /** @dev Deserializs userop calldata for easier integration into any dapp
      *      Warning: this function is low-level manipulation
      */
    function _decodeUserOperation() public returns (UserOperation memory) {
        bytes32 messageId;
        uint256 sourceChainSelector;
        bytes memory sender;
        address uoSender;
        uint256 uoNonce;
        bytes memory uoInitCode;
        bytes memory uoCallData;
        uint256 messageSize;
        uint256 uoCallGasLimit;
        uint256 uoVerificationGasLimit;
        uint256 uoPreVerificationGas;
        uint256 uoMaxFeePerGas;
        uint256 uoMaxPriorityFeePerGas;
        bytes memory uoPaymasterAndData;
        bytes memory uoSignature;
        uint256 dummy;
        Client.EVMTokenAmount memory destTokenAmounts;
        assembly {
            let len := mload(0x20)
            let ptr := mload(0x40)
            let offset := 0x4

            // ================================================================
            // begin deserialize CCIP message
            calldatacopy(ptr, add(offset, 0x20), 0x20)
            messageId := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x40), 0x20)
            sourceChainSelector := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x60), 0x20) // string size ref
            calldatacopy(ptr, add(mload(ptr), 0x4), 0x20)
            messageSize := mload(ptr) // not used
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x80), 0x20)
            calldatacopy(len, add(sub(mload(ptr), 0x20), 0x4), 0x20)
            calldatacopy(ptr, add(mload(ptr), 0x4), mload(len))
            sender := mload(ptr)
            // ================================================================
            // begin deserialize user operation
            calldatacopy(ptr, add(offset, 0x100), 0x20)
            offset := add(offset, 0x120)
            // ----------------------------------------------------------------
            calldatacopy(ptr, offset, 0x20)
            calldatacopy(ptr, add(mload(ptr), offset), 0x20)
            uoSender := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x40), 0x20)
            uoNonce := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x60), 0x20)
            uoInitCode := mload(ptr) // ref
            calldatacopy(ptr, add(offset, 0x80), 0x20)
            uoCallData := mload(ptr) // ref
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0xA0), 0x20)
            uoCallGasLimit := mload(ptr)
            calldatacopy(ptr, add(offset, 0xC0), 0x20)
            uoVerificationGasLimit := mload(ptr)
            calldatacopy(ptr, add(offset, 0xE0), 0x20)
            uoPreVerificationGas := mload(ptr)
            calldatacopy(ptr, add(offset, 0x100), 0x20)
            uoMaxFeePerGas := mload(ptr)
            calldatacopy(ptr, add(offset, 0x120), 0x20)
            uoMaxPriorityFeePerGas := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x140), 0x20)
            uoPaymasterAndData := mload(ptr) // ref
            calldatacopy(ptr, add(offset, 0x160), 0x20)
            uoSignature := mload(ptr) // ref
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoInitCode, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoInitCode, add(offset, 0x40)), mload(len))
                uoInitCode := mload(ptr)
            }
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoCallData, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                //calldatacopy(ptr, add(uoCallData, add(offset, 0x20)), mload(add(len, 0x20)))
                calldatacopy(ptr, add(uoCallData, add(offset, 0x40)), mload(len))
                uoCallData := mload(ptr)
            }
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoPaymasterAndData, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoPaymasterAndData, add(offset, 0x20)), add(mload(len), 0x20))
                //calldatacopy(ptr, add(uoPaymasterAndData, add(offset, 0x40)), mload(len))
                uoPaymasterAndData := mload(ptr)
                dummy := mload(ptr)
                dummy := mload(add(ptr, 0x20)) // correct
                mstore(ptr, uoPaymasterAndData)
                dummy := mload(add(ptr, 0x40)) // gave 288
            }
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoSignature, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoSignature, add(offset, 0x40)), mload(len))
                uoSignature := mload(ptr)
            }
            // ================================================================
            // continue CCIP deserialization
            calldatacopy(ptr, sub(offset, 0x20), 0x20)
            offset := add(offset, mload(ptr))
            // ----------------------------------------------------------------
            calldatacopy(len, offset, 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(offset, 0x20), mload(len))
                destTokenAmounts := mload(ptr)
            }
            calldatacopy(len, offset, 0x20)


            
            // ================================================================
            // CCIP UserOp referance sheet
            // ================================================================
            // 0x // messageId (bytes32)
            // 0000000000000000000000000000000000000000000000000000000000000020
            // 00000000000000000000000000000000000000000000000000000000000003e8
            // sourceChainSelector
            // 000000000000000000000000000000000000000000000000b63e800d00000000
            // wtf is this? data string size ref
            // 00000000000000000000000000000000000000000000000000000000000000a0
            // sender ref
            // 00000000000000000000000000000000000000000000000000000000000000e0
            // wtf is this? data string size
            // 00000000000000000000000000000000000000000000000000000000000005a0
            // sender (message)
            // 0000000000000000000000000000000000000000000000000000000000000020
            // 7fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000
            // ================================================================
            // data start
            // 00000000000000000000000000000000000000000000000000000000000004a0
            // ----------------------------------------------------------------
            // sender (userop)
            // 0000000000000000000000000000000000000000000000000000000000000020
            // ff65689a4aeb6eadd18cad2de0022f8aa18b67de000000000000000000000000
            // ----------------------------------------------------------------
            // nonce
            // 00000000000000000000000000000000000000000000000000000000000000f0
            // ----------------------------------------------------------------
            // initCode ref
            // 0000000000000000000000000000000000000000000000000000000000000160
            // callData ref
            // 0000000000000000000000000000000000000000000000000000000000000180
            // ----------------------------------------------------------------
            // callGasLimit
            // 0000000000000000000000000000000000000000000000000000000000989680
            // verificationGasLimit
            // 0000000000000000000000000000000000000000000000000000000001312d00
            // preVerificationGas
            // 0000000000000000000000000000000000000000000000000000000001312d00
            // maxFeePerGas
            // 0000000000000000000000000000000000000000000000000000000000000002
            // maxPriorityFeePerGas
            // 0000000000000000000000000000000000000000000000000000000000000001
            // ----------------------------------------------------------------
            // paymasterAndData ref
            // 0000000000000000000000000000000000000000000000000000000000000340
            // signature ref
            // 0000000000000000000000000000000000000000000000000000000000000400
            // ----------------------------------------------------------------
            // initCode size
            // 0000000000000000000000000000000000000000000000000000000000000000
            // ----------------------------------------------------------------
            // callData size
            // 0000000000000000000000000000000000000000000000000000000000000184
            // b61d27f6 // calldata
            // 000000000000000000000000c532a74256d3db42d0bf7a0400fefdbad7694008
            // 00000000000000000000000000000000000000000000000000038d7ea4c68000
            // 0000000000000000000000000000000000000000000000000000000000000060
            // 00000000000000000000000000000000000000000000000000000000000000e4
            // 7ff36ab500000000000000000000000000000000000000000000000000000000
            // 0000000000000000000000000000000000000000000000000000000000000000
            // 0000008000000000000000000000000052eb5d94da6146836b0a6c542b69545d
            // d35fda6d00000000000000000000000000000000000000000000000000000000
            // 669e545500000000000000000000000000000000000000000000000000000000
            // 000000020000000000000000000000007b79995e5f793a07bc00c21412e50eca
            // e098e7f9000000000000000000000000ae0086b0f700d6d7d4814c4ba1e55d3b
            // c0dfee0200000000000000000000000000000000000000000000000000000000
            // 00000000000000000000000000000000000000000000000000000000
            // ----------------------------------------------------------------
            // paymasterAndData
            // 00000000000000000000000000000000000000000000000000000000000000a0
            // 0000000000000000000000000000000000000000000000000000000000000000
            // 0000000000000000000000000000000000000000000000000000000000000000
            // 0000000000000000000000000000000000000000000000000000000000000000
            // 0000000000000000000000000000000000000000000000000000000000000000
            // 0000000000000000000000000000000000000000000000000000000000000000
            // ----------------------------------------------------------------
            // signature
            // 0000000000000000000000000000000000000000000000000000000000000041
            // 190999a8ab31185b0c415c5e1fbb48dd71429e0fee42c1d1c82bfa27b07a7097
            // 29a859e59fb4721398502b92b2ff0696ee130b489a1347182f92bfa33fd11f0f
            // 1b00000000000000000000000000000000000000000000000000000000000000
            // data end
            // ================================================================
            // destTokenAmounts
            // 0000000000000000000000000000000000000000000000000000000000000000
        }
        //revert((dummy).toString());

        return UserOperation(
            uoSender,
            uint256(uoNonce),
            uoInitCode,
            uoCallData,
            uint256(uoCallGasLimit),
            uint256(uoVerificationGasLimit),
            uint256(uoPreVerificationGas),
            uint256(uoMaxFeePerGas),
            uint256(uoMaxPriorityFeePerGas),
            uoPaymasterAndData,
            uoSignature
        );
    }

    function _decodeUserOperation(bytes memory data) public returns (UserOperation memory) {
        address uoSender;
        uint256 uoNonce;
        bytes memory uoInitCode;
        bytes memory uoCallData;
        uint256 uoCallGasLimit;
        uint256 uoVerificationGasLimit;
        uint256 uoPreVerificationGas;
        uint256 uoMaxFeePerGas;
        uint256 uoMaxPriorityFeePerGas;
        bytes memory uoPaymasterAndData;
        bytes memory uoSignature;

        assembly {
            let len := mload(0x20)
            let ptr := mload(0x40)
            let offset := 0x4

            calldatacopy(ptr, offset, 0x20)
            calldatacopy(ptr, add(mload(ptr), offset), 0x20)
            uoSender := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x40), 0x20)
            uoNonce := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x60), 0x20)
            uoInitCode := mload(ptr) // ref
            calldatacopy(ptr, add(offset, 0x80), 0x20)
            uoCallData := mload(ptr) // ref
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0xA0), 0x20)
            uoCallGasLimit := mload(ptr)
            calldatacopy(ptr, add(offset, 0xC0), 0x20)
            uoVerificationGasLimit := mload(ptr)
            calldatacopy(ptr, add(offset, 0xE0), 0x20)
            uoPreVerificationGas := mload(ptr)
            calldatacopy(ptr, add(offset, 0x100), 0x20)
            uoMaxFeePerGas := mload(ptr)
            calldatacopy(ptr, add(offset, 0x120), 0x20)
            uoMaxPriorityFeePerGas := mload(ptr)
            // ----------------------------------------------------------------
            calldatacopy(ptr, add(offset, 0x140), 0x20)
            uoPaymasterAndData := mload(ptr) // ref
            calldatacopy(ptr, add(offset, 0x160), 0x20)
            uoSignature := mload(ptr) // ref
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoInitCode, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoInitCode, add(offset, 0x40)), mload(len))
                uoInitCode := mload(ptr)
            }
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoCallData, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoCallData, add(offset, 0x40)), mload(len))
                uoCallData := mload(ptr)
            }
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoPaymasterAndData, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoPaymasterAndData, add(offset, 0x40)), mload(len))
                uoPaymasterAndData := mload(ptr)
            }
            // ----------------------------------------------------------------
            calldatacopy(len, add(uoSignature, add(offset, 0x20)), 0x20)
            switch iszero(len)
            case 0 {
                calldatacopy(ptr, add(uoSignature, add(offset, 0x40)), mload(len))
                uoSignature := mload(ptr)
            }
        }

        return UserOperation(
            uoSender,
            uint256(uoNonce),
            uoInitCode,
            uoCallData,
            uint256(uoCallGasLimit),
            uint256(uoVerificationGasLimit),
            uint256(uoPreVerificationGas),
            uint256(uoMaxFeePerGas),
            uint256(uoMaxPriorityFeePerGas),
            uoPaymasterAndData,
            uoSignature
        );
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
        //PaymasterAndData memory paymasterAndData = abi.decode(mUserOp.paymasterAndData, (PaymasterAndData));

        // address paymaster_;// = address(bytes20(mUserOp[:20]));
        // address owner_;// = address(bytes20(mUserOp[20:40]));
        // uint32 chainId_;// = uint32(uint256(bytes32(mUserOp[40:72])));
        // address paymentAsset_;// = address(bytes20(mUserOp[72:92]));
        // uint256 paymentAmount_;// = uint256(bytes32(mUserOp[92:124]));

        // assembly {
        //     paymaster_ := and(mload(add(paymasterAndData_, 32)), 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000)
        //     owner_ := and(mload(add(paymasterAndData_, 52)), 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000)
        //     chainId_ := mload(add(paymasterAndData_, 40))
        //     paymentAsset_ := and(mload(add(paymasterAndData_, 72)), 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000)
        //     paymentAmount_ := and(mload(add(paymasterAndData_, 92)), 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000)
        // }

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
        // revert((uint256(uint160(paymasterAndData_.owner))).toString());

        if(paymasterAndData_.paymaster == address(0)) { revert InvalidPaymaster(paymasterAndData_.paymaster); }
        if(paymasterAndData_.chainId == uint256(0)) { revert InvalidChain(paymasterAndData_.chainId); }
        if(paymasterAndData_.owner == address(0)) { revert InvalidOwner(paymasterAndData_.owner); }
        if(paymasterAndData_.owner == address(this)) { revert InvalidOwner(paymasterAndData_.owner); }

        Escrow storage accountInfo_ = _accountInfo[paymasterAndData_.owner];
        if(block.timestamp > accountInfo_.deadline) { revert InvalidDeadline(""); }
        
        // revert(uint256(uint160(paymasterAndData.owner)).toString());
        // revert(uint256(_accountInfo[paymasterAndData.owner].assetBalance[paymasterAndData.asset]).toString());
        
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

    function handleMessage(Client.Any2EVMMessage memory message) payable external locked {
        if(!ccipAddress[msg.sender]) {
            revert InvalidCCIPAddress(msg.sender);
        }

        // deserialize userop and paymasterAndData
        (UserOperation memory mUserOp, address receiver_) = abi.decode(message.data, (UserOperation, address));
        PaymasterAndData memory paymasterAndData = abi.decode(mUserOp.paymasterAndData, (PaymasterAndData));

        // hash userop locally
        bytes memory payload_ = abi.encodeWithSelector(bytes4(0x7b1d0da3), mUserOp);
        bytes32 userOpHash;
        assembly {
            pop(call(gas(), address(), 0, add(payload_, 0x20), mload(payload_), 0, 0x20))
            userOpHash := mload(0)
        }
        userOpHash = keccak256(abi.encode(
            userOpHash, 
            _entryPoint[paymasterAndData.chainId], 
            uint256(paymasterAndData.chainId)
        ));
        
        // validate signature
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(userOpHash.toEthSignedMessageHash(), mUserOp.signature);
        if (error != ECDSA.RecoverError.NoError) {
            revert BadSignature();
        } else {
            if(recovered != paymasterAndData.owner) {
                revert InvalidSignature(paymasterAndData.owner, recovered);
            }
        }
        //revert((uint256(uint160(paymasterAndData.owner))).toString());

        if(paymasterAndData.paymaster == address(0)) { revert InvalidPaymaster(paymasterAndData.paymaster); }
        if(paymasterAndData.chainId == uint256(0)) { revert InvalidChain(paymasterAndData.chainId); }
        if(paymasterAndData.owner == address(0)) { revert InvalidOwner(paymasterAndData.owner); }
        if(paymasterAndData.owner == address(this)) { revert InvalidOwner(paymasterAndData.owner); }

        Escrow storage accountInfo_ = _accountInfo[paymasterAndData.owner];
        if(block.timestamp > accountInfo_.deadline) { revert InvalidDeadline(""); }
        
        // revert(uint256(uint160(paymasterAndData.owner)).toString());
        // revert(uint256(_accountInfo[paymasterAndData.owner].assetBalance[paymasterAndData.asset]).toString());
        
        // Transfer amount of asset to receiver
        bool success_;
        address asset_ = paymasterAndData.asset;
        if(accountInfo_.assetBalance[asset_] < paymasterAndData.amount) { 
            revert InsufficentFunds(paymasterAndData.owner, asset_, paymasterAndData.amount);
        }

        if(asset_ == address(0)) { // address(0) == ETH
            (success_,) = payable(receiver_).call{value: paymasterAndData.amount}("");
        } else {
            // insufficent address(this) balance will auto-revert
            payload_ = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", 
                address(this), 
                receiver_, 
                paymasterAndData.amount
            );
            assembly {
                success_ := call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0, 0)
            }
        }
        if(!success_) { 
            revert PaymasterPaymentFailed(
                receiver_, 
                asset_, 
                paymasterAndData.owner, 
                paymasterAndData.amount
            );
        }
        accountInfo_.history[accountInfo_.nonce] = Payment(
            block.timestamp,
            paymasterAndData.amount,
            uint256(message.messageId),
            paymasterAndData.chainId,
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

        emit PrintUserOp(mUserOp, paymasterAndData);
    }
// struct Any2EVMMessage {
//     bytes32 messageId; // MessageId corresponding to ccipSend on source.
//     uint64 sourceChainSelector; // Source chain selector.
//     bytes sender; // abi.decode(sender) if coming from an EVM chain.
//     bytes data; // payload sent in original message.
//     EVMTokenAmount[] destTokenAmounts; // Tokens and their amounts in their destination chain representation.
//   }
    function printOp(Client.Any2EVMMessage memory message) payable external locked {
        if(!ccipAddress[msg.sender]) {
            revert InvalidCCIPAddress(msg.sender);
        }

        // deserialize userop and paymasterAndData
        (UserOperation memory mUserOp, address receiver_) = abi.decode(message.data, (UserOperation, address));
        PaymasterAndData memory paymasterAndData = abi.decode(mUserOp.paymasterAndData, (PaymasterAndData));

        // hash userop locally
        bytes memory payload_ = abi.encodeWithSelector(bytes4(0x7b1d0da3), mUserOp);
        bytes32 userOpHash;
        assembly {
            pop(call(gas(), address(), 0, add(payload_, 0x20), mload(payload_), 0, 0x20))
            userOpHash := mload(0)
        }
        userOpHash = keccak256(abi.encode(
            userOpHash, 
            _entryPoint[paymasterAndData.chainId], 
            uint256(paymasterAndData.chainId)
        ));
        
        // validate signature
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(userOpHash.toEthSignedMessageHash(), mUserOp.signature);
        if (error != ECDSA.RecoverError.NoError) {
            revert BadSignature();
        } else {
            if(recovered != paymasterAndData.owner) {
                revert InvalidSignature(paymasterAndData.owner, recovered);
            }
        }
        //revert((uint256(uint160(paymasterAndData.owner))).toString());

        if(paymasterAndData.paymaster == address(0)) { revert InvalidPaymaster(paymasterAndData.paymaster); }
        if(paymasterAndData.chainId == uint256(0)) { revert InvalidChain(paymasterAndData.chainId); }
        if(paymasterAndData.owner == address(0)) { revert InvalidOwner(paymasterAndData.owner); }
        if(paymasterAndData.owner == address(this)) { revert InvalidOwner(paymasterAndData.owner); }

        Escrow storage accountInfo_ = _accountInfo[paymasterAndData.owner];
        if(block.timestamp > accountInfo_.deadline) { revert InvalidDeadline(""); }
        
        // revert(uint256(uint160(paymasterAndData.owner)).toString());
        // revert(uint256(_accountInfo[paymasterAndData.owner].assetBalance[paymasterAndData.asset]).toString());
        
        // Transfer amount of asset to receiver
        bool success_;
        address asset_ = paymasterAndData.asset;
        if(accountInfo_.assetBalance[asset_] < paymasterAndData.amount) { 
            revert InsufficentFunds(paymasterAndData.owner, asset_, paymasterAndData.amount);
        }

        if(asset_ == address(0)) { // address(0) == ETH
            (success_,) = payable(receiver_).call{value: paymasterAndData.amount}("");
        } else {
            // insufficent address(this) balance will auto-revert
            payload_ = abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", 
                address(this), 
                receiver_, 
                paymasterAndData.amount
            );
            assembly {
                success_ := call(gas(), asset_, 0, add(payload_, 0x20), mload(payload_), 0, 0)
            }
        }
        if(!success_) { 
            revert PaymasterPaymentFailed(
                receiver_, 
                asset_, 
                paymasterAndData.owner, 
                paymasterAndData.amount
            );
        }
        accountInfo_.history[accountInfo_.nonce] = Payment(
            block.timestamp,
            paymasterAndData.amount,
            uint256(message.messageId),
            paymasterAndData.chainId,
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

        emit PrintUserOp(mUserOp, paymasterAndData);
    }
    
    /*
    Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
                receiver: abi.encode(receiver),
                data: abi.encode(messageText),
                tokenAmounts: new Client.EVMTokenAmount[](0),
                extraArgs: "",
                feeToken: payFeesIn == PayFeesIn.LINK ? i_link : address(0)
            });

    */
    function callPrintOp(Client.Any2EVMMessage memory message) payable external locked {
        // validate msg.sender is ccip source
        // cast data into userop
        // ignore the rest
        if(!ccipAddress[msg.sender]) {
            revert InvalidCCIPAddress(msg.sender);
        }
        // UserOperation calldata userOp;// = _calldataUserOperation(_decodeUserOperation(message.data));
        // PaymasterAndData memory data = _decodePaymasterAndData(userOp.paymasterAndData);

        // // authenticate the operation
        // bytes32 userOpHash = userOp.hash();
        // // need to check safe signature method (maybe ecdsa?)

        // if(data.chainId != block.chainid) {
        //     revert InvalidChain(data.chainId);
        // }
        // if(data.amount < address(this).balance) {
        //     revert BalanceError(data.amount, address(this).balance);
        // }
    }

    event PrintUserOp(UserOperation userOp, PaymasterAndData paymasterAndData);

    fallback() external payable {}
}
