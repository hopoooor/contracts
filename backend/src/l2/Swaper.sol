// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@arbitrum/nitro-contracts/src/libraries/AddressAliasHelper.sol";
import {WETH} from "@rari-capital/solmate/src/tokens/WETH.sol";
import 'uniswap/contracts/libraries/TransferHelper.sol';
import 'uniswap/contracts/interfaces/ISwapRouter.sol';

contract Swaper {

    address public l1Target;

    ISwapRouter public immutable swapRouter;

    uint24 public constant poolFee = 3000;

    constructor(address _l1Target, address _swapRouter) {
        swapRouter = ISwapRouter(_swapRouter);
        l1Target = _l1Target;
    }

    /// @dev Callback for receiving ether when the calldata is empty
    receive() external payable {}

    function swapExactInputSingle(address input, address output, uint256 amountIn, address recipient) external returns (uint256 amountOut) {
        require(
            msg.sender == AddressAliasHelper.applyL1ToL2Alias(l1Target),
            "Swapper only callable by l1Target"
        );

        
        address tokenIn;
        if(input == address(0)) {
            WETH(payable(0xF4e3B0de5021d400A3D2F4A5F286593D447d7569)).deposit{value: amountIn}();
            tokenIn = 0xF4e3B0de5021d400A3D2F4A5F286593D447d7569;
        } else {
            tokenIn = input;
        }

        TransferHelper.safeApprove(input, address(swapRouter), amountIn);
        // Naively set amountOutMinimum to 0. In production, use an oracle or other data source to choose a safer value for amountOutMinimum.
        // We also set the sqrtPriceLimitx96 to be 0 to ensure we swap our exact input amount.
        ISwapRouter.ExactInputSingleParams memory params =
            ISwapRouter.ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: output,
                fee: poolFee,
                recipient: recipient,
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: 0,
                sqrtPriceLimitX96: 0
            });

        // The call to `exactInputSingle` executes the swap.
        amountOut = swapRouter.exactInputSingle(params);
    }
    
}
