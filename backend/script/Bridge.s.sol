// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import "forge-std/Script.sol";
import "../src/Bridge.sol";

contract BridgeScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        Bridge bridge = new Bridge(0x018c1b0a0149fD2Af4D3384d1Cc1884d082a6BB5, 0x6BEbC4925716945D46F0Ec336D5C2564F419682C);
        console.log("Bridge Address: ");
        console.log(address(bridge));
        vm.stopBroadcast();
    }
}

