// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "arb-bridge-eth/bridge/Inbox.sol";
import {Swaper} from "./l2/Swaper.sol";
import {IL1_Bridge} from "./hop/IL1_Bridge.sol";

struct BridgeParams {
    uint256 chainId;
    address recipient;
    uint256 amount;
    uint256 amountOutMin;
    uint256 deadline;
    address relayer;
    uint256 relayerFee;
}

struct InboxParams {
    uint256 maxSubmissionCost;
    uint256 maxGas;
    uint256 gasPriceBid;
}

contract Bridge {
    /// @dev Minimum reserve of gas units
    uint256 private constant MIN_GAS_RESERVE = 5_000;
    // Target address for swap
    address public l2SwapTarget;
    // Nitro Inbox contract
    IInbox public inbox;

    /// @dev Emitted when execution reverted with no reason
    error ExecutionReverted();
    /// @dev Emitted when passing an EOA or an undeployed contract as the target
    error InvalidBridge(address _bridge);

    event RetryableTicketCreated(uint256 indexed ticketId);

    constructor(address _l2SwapTarget, address _inbox) {
        l2SwapTarget = _l2SwapTarget;
        inbox = IInbox(_inbox);
    }
    
    // Note: token addresses need to be L2 token addresses
    function sendAndSwap(
        BridgeParams calldata bridgeParams,
        InboxParams calldata inboxParams,
        address l1Bridge,
        address l2tokenIn,
        address l2tokenOut
    ) external payable returns (uint256) {

        {
            if (l1Bridge.code.length == 0) revert InvalidBridge(l1Bridge);
            // Reserve some gas to ensure that the function has enough to finish the execution
            uint256 stipend = gasleft() - MIN_GAS_RESERVE;
            
            bytes memory hopData = abi.encodeWithSelector(
                IL1_Bridge.sendToL2.selector, 
                bridgeParams.chainId,
                l2SwapTarget,
                bridgeParams.amount,
                bridgeParams.amountOutMin,
                bridgeParams.deadline,
                bridgeParams.relayer,
                bridgeParams.relayerFee
            );

            (bool success, bytes memory response) = l1Bridge.delegatecall{gas: stipend}(hopData);

            if (!success) {
                if (response.length == 0) revert ExecutionReverted();
                _revertedWithReason(response);
            }
        }   
        
        {
            // Send L1 -> L2 message to swap tokens
            bytes memory data = abi.encodeWithSelector(
                Swaper.swapExactInputSingle.selector, 
                l2tokenIn,
                l2tokenOut,
                bridgeParams.amount,
                bridgeParams.recipient
            );

            // Create retriable ticket
            uint256 ticketID = inbox.createRetryableTicket{ value: msg.value }(
                l2SwapTarget,
                0,
                inboxParams.maxSubmissionCost,
                msg.sender,
                msg.sender,
                inboxParams.maxGas,
                inboxParams.gasPriceBid,
                data
            );

            emit RetryableTicketCreated(ticketID);
            return ticketID;
        }
        
    }

    /// @notice Reverts transaction with reason
    /// @param _response Unsucessful return response of the delegate call
    function _revertedWithReason(bytes memory _response) internal pure {
        assembly {
            let returndata_size := mload(_response)
            revert(add(32, _response), returndata_size)
        }
    }
}
