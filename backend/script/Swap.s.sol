// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/l2/Swaper.sol";

contract Swap is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        Swaper swaper = new Swaper(0xAca2A7b4dc793e3EdCB46663768E6F261201AF3a, 0x4385F008Ebc3B0B224904Aa1FEde9E7230D7F9C9);
        console.log("Swaper Address: ");
        console.log(address(swaper));
        vm.stopBroadcast();
    }
}

