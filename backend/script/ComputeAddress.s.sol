// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";

import "forge-std/Script.sol";

contract ComputeAddress is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        uint256 nonce = vm.getNonce(0xFb8C3ba8A46014400487f2fB4d539A5Ff7bC367D);
        address computedAddress = computeCreateAddress(0xFb8C3ba8A46014400487f2fB4d539A5Ff7bC367D, nonce);
        console.log("Nonce: ");
        console.log(nonce);
        console.log("Computed address: ");
        console.log(computedAddress);
        vm.stopBroadcast();
    }
}