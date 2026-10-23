// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";
import {AnnouncementRegistry} from "../src/AnnouncementRegistry.sol";

/// @notice Deploys the verifier and the registry through the CREATE2 deployer, so
///         both addresses follow from the code and the key set alone. Running it
///         without --broadcast prints the addresses without deploying.
///
///     KEYS=$(mfreg keys <keys-dir>) forge script script/Deploy.s.sol --rpc-url $RPC [--broadcast ...]
contract Deploy is Script {
    function run() external returns (HonkVerifier verifier, AnnouncementRegistry registry) {
        bytes[] memory keys = vm.envBytes("KEYS", ",");

        vm.startBroadcast();
        verifier = new HonkVerifier{salt: bytes32(0)}();
        registry = new AnnouncementRegistry{salt: bytes32(0)}(verifier, keys);
        vm.stopBroadcast();

        console.log("verifier", address(verifier));
        console.log("registry", address(registry));
    }
}
