// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.15;

import "../test/base/loadkey.t.sol";
import "forge-std/console.sol";

contract Deploy is LoadKey {
    // using UserOperationLib for UserOperation;

    function setUp() public virtual override {
        super.setUp();
    }

    function run() public {
        vm.startBroadcast(privateKey);
        vm.stopBroadcast();
    }

}
