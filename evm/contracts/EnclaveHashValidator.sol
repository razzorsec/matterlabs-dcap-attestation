// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {Ownable} from "solady/auth/Ownable.sol";
import {IEnclaveHashValidator} from "./interfaces/IEnclaveHashValidator.sol";
/**
 * @title EnclaveHashValidator
 * @dev Manages a set of valid hashes with batch operations for efficiency.
 */
contract EnclaveHashValidator is Ownable, IEnclaveHashValidator {
    mapping(bytes32 => bool) private validEnclaveHashes;
    event EnclaveHashesUpdated(bytes32[] hashes, bool status);

    constructor(address owner) {
        _initializeOwner(owner);
    }

    /**
     * @notice Adds multiple enclave hashes to the valid list in a batch.
     * @param hashes The array of hashes to be marked as valid.
     */
    function addValidEnclaveHashes(bytes32[] calldata hashes) external onlyOwner {
        for (uint256 i = 0; i < hashes.length; ++i) {
            validEnclaveHashes[hashes[i]] = true;
        }
        emit EnclaveHashesUpdated(hashes, true);

    }

    /**
     * @notice Removes multiple enclave hashes from the valid list in a batch.
     * @param hashes The array of hashes to be removed.
     */
    function removeValidEnclaveHashes(bytes32[] calldata hashes) external onlyOwner {
        for (uint256 i = 0; i < hashes.length; ++i) {
            validEnclaveHashes[hashes[i]] = false;
        }
        emit EnclaveHashesUpdated(hashes, false);

    }

    /**
     * @notice Checks if a given enclave hash is valid.
     * @param hash The hash to check.
     * @return isValid True if the hash is valid, false otherwise.
     */
    function isValidEnclaveHash(bytes32 hash) external view returns (bool isValid) {
        return validEnclaveHashes[hash];
    }
}
