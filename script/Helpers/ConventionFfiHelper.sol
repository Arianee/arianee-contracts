// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";

struct Convention {
    uint256 chainId;
    string rpcUrl;
    string gasStation;
    address aria;
    address creditHistory;
    address rewardsHistory;
    address eventArianee;
    address identity;
    address smartAsset;
    address staking;
    address store;
    address whitelist;
    address lost;
    address message;
    address userAction;
    address updateSmartAssets;
    address hasher;
    address creditRegister;
    address creditVerifier;
    address creditNotePool;
    address poseidon;
    address ownershipVerifier;
    address issuerProxy;
}

/**
 * @title ConventionFfiHelper
 * @notice Helper contract to interact with the convention script
 */
abstract contract ConventionFfiHelper is Script {
    function writeConventionFile(
        Convention memory convention
    ) internal returns (bool) {
        string[] memory inputs = new string[](24);
        inputs[0] = "./write-convention-file.sh";
        inputs[1] = string(abi.encodePacked("--chainId=", vm.toString(convention.chainId)));
        inputs[2] = string(abi.encodePacked("--httpProvider=", convention.rpcUrl));
        inputs[3] = string(abi.encodePacked("--gasStation=", convention.gasStation));
        inputs[4] = string(abi.encodePacked("--aria=", vm.toString(convention.aria)));
        inputs[5] = string(abi.encodePacked("--creditHistory=", vm.toString(convention.creditHistory)));
        inputs[6] = string(abi.encodePacked("--rewardsHistory=", vm.toString(convention.rewardsHistory)));
        inputs[7] = string(abi.encodePacked("--eventArianee=", vm.toString(convention.eventArianee)));
        inputs[8] = string(abi.encodePacked("--identity=", vm.toString(convention.identity)));
        inputs[9] = string(abi.encodePacked("--smartAsset=", vm.toString(convention.smartAsset)));
        inputs[10] = string(abi.encodePacked("--staking=", vm.toString(convention.staking)));
        inputs[11] = string(abi.encodePacked("--store=", vm.toString(convention.store)));
        inputs[12] = string(abi.encodePacked("--whitelist=", vm.toString(convention.whitelist)));
        inputs[13] = string(abi.encodePacked("--lost=", vm.toString(convention.lost)));
        inputs[14] = string(abi.encodePacked("--message=", vm.toString(convention.message)));
        inputs[15] = string(abi.encodePacked("--userAction=", vm.toString(convention.userAction)));
        inputs[16] = string(abi.encodePacked("--updateSmartAssets=", vm.toString(convention.updateSmartAssets)));
        inputs[17] = string(abi.encodePacked("--hasher=", vm.toString(convention.hasher)));
        inputs[18] = string(abi.encodePacked("--creditRegister=", vm.toString(convention.creditRegister)));
        inputs[19] = string(abi.encodePacked("--creditVerifier=", vm.toString(convention.creditVerifier)));
        inputs[20] = string(abi.encodePacked("--creditNotePool=", vm.toString(convention.creditNotePool)));
        inputs[21] = string(abi.encodePacked("--poseidon=", vm.toString(convention.poseidon)));
        inputs[22] = string(abi.encodePacked("--ownershipVerifier=", vm.toString(convention.ownershipVerifier)));
        inputs[23] = string(abi.encodePacked("--issuerProxy=", vm.toString(convention.issuerProxy)));
        bytes memory res = vm.ffi(inputs);
        return abi.decode(res, (bool));
    }
}
