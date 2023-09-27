// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {HyperlaneMailbox} from "./HyperlaneMailbox.sol";

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

contract HyperlaneIGP is IIGP {
    HyperlaneMailbox _hyperlaneMailbox;
    constructor(address hyperlaneMailbox_) {
        _hyperlaneMailbox = HyperlaneMailbox(payable(hyperlaneMailbox_));
    }

    function payForGas(
        bytes32 _messageId,
        uint32 _destinationDomain,
        uint256 _gasAmount,
        address _refundAddress
    ) external payable {
        (_destinationDomain, _gasAmount); // unused
        _hyperlaneMailbox.payMessage{value: msg.value}(_messageId, _refundAddress);
    }

    function quoteGasPayment(uint32 _destinationDomain, uint256 _gasAmount)  external view returns (uint256) {
        return 0.001 ether;
    }

    receive() external payable {}
}