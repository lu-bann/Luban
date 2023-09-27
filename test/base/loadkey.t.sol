// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

 contract LoadKey is Test {

    address eoaAddress;
    bytes32 internal key_bytes;
    uint256 internal privateKey;

    function setUp() public virtual {
        // setup private key
        string memory key = vm.readFile(".secret");
        key_bytes = vm.parseBytes32(key);
        assembly {
            sstore(privateKey.slot, sload(key_bytes.slot))
        }
        eoaAddress = vm.addr(privateKey);
    }

 }