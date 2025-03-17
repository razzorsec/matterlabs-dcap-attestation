// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title IEnclaveHashValidator
 * @notice Interface for managing valid enclave hashes.
 */
interface IEnclaveHashValidator {
    function addValidEnclaveHashes(bytes32[] calldata hashes) external;
    function removeValidEnclaveHashes(bytes32[] calldata hashes) external;
    function isValidEnclaveHash(bytes32 hash) external view returns (bool);
}
