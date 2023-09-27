//SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity^0.8.17;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Token is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) payable {}

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}