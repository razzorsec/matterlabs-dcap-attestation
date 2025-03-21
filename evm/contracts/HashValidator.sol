// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {Ownable} from "solady/auth/Ownable.sol";
import "./interfaces/IHashValidator.sol";

/**
 * @title EnclaveHashValidator
 * @dev Manages a set of valid hashes with batch operations for efficiency.
 */
contract HashValidator is Ownable, IHashValidator {
    
    uint256 constant totalValidRtMrCount = 4;
    mapping(bytes32 => bool) private validEnclaveHashes;
    mapping(bytes => bool) private validTD10MrTDHashes;
    mapping(uint256 => mapping(bytes => bool)) private validRtMrHashes;

    error ArrayLengthsMismatch();
    error EmptyArray();

    event EnclaveHashesUpdated(bytes32[] hashes, bool status);
    event TD10MrTDHashesUpdated(bytes[] hashes, bool status);
    event RtMrHashesUpdated(uint256[] rtMrX, bytes[] hashes, bool status);

    constructor(address owner) {
        _initializeOwner(owner);
    }

    /**
     * @notice Adds multiple enclave hashes to the valid list.
     * @param hashes The array of hashes to be marked as valid.
     */
    function addValidEnclaveHashes(bytes32[] calldata hashes) external onlyOwner {
        for (uint256 i = 0; i < hashes.length; ++i) {
            validEnclaveHashes[hashes[i]] = true;
        }
        emit EnclaveHashesUpdated(hashes, true);

    }

    /**
     * @notice Removes multiple enclave hashes from the valid list.
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

    /**
     * @notice Adds multiple TD10 MrTD hashes to the valid list.
     * @param hashes The array of hashes to be marked as valid.
     */
    function addValidTD10MrTDHashes(bytes[] calldata hashes) external onlyOwner{
        for (uint256 i = 0; i < hashes.length; ++i) {
            validTD10MrTDHashes[hashes[i]] = true;
        }
        emit TD10MrTDHashesUpdated(hashes, true);
    }

    /**
     * @notice Removes multiple TD10 MrTD hashes from the valid list.
     * @param hashes The array of hashes to be removed.
     */
    function removeValidTD10MrTDHashes(bytes[] calldata hashes) external onlyOwner{
        for (uint256 i = 0; i < hashes.length; ++i) {
            validTD10MrTDHashes[hashes[i]] = false;
        }
        emit TD10MrTDHashesUpdated(hashes, false);

    }

    /**
     * @notice Checks if a given TD10 MrTD hash is valid.
     * @param hash The hash to check.
     * @return isValid True if the hash is valid, false otherwise.
     */
    function isValidTD10MrTDHash(bytes calldata hash) external view returns(bool isValid){
        return validTD10MrTDHashes[hash];
    }

    /**
     * @notice Adds multiple RtMr hashes associated with different indices.
     * @param rtMrX The array of RtMr indices.
     * @param hashes The array of hashes corresponding to each index.
     */
    function addValidRtMrHashes(uint256[] calldata rtMrX, bytes[] calldata hashes) external onlyOwner{
        uint256 rtMrXCount = rtMrX.length;
        require(rtMrXCount > 0, EmptyArray());
        require(rtMrXCount == hashes.length, ArrayLengthsMismatch());
        for(uint256 i = 0; i < rtMrXCount; ++i){
            if(rtMrX[i] < totalValidRtMrCount){
                validRtMrHashes[rtMrX[i]][hashes[i]] = true;
            }
        }
        emit RtMrHashesUpdated(rtMrX, hashes, true);
    }  

    /**
     * @notice Removes multiple RtMr hashes associated with different indices.
     * @param rtMrX The array of RtMr indices.
     * @param hashes The array of hashes corresponding to each index.
     */
    function removeValidRtMrHashes(uint256[] calldata rtMrX, bytes[] calldata hashes) external onlyOwner{
        uint256 rtMrXCount = rtMrX.length;
        require(rtMrXCount > 0, EmptyArray());
        require(rtMrXCount == hashes.length, ArrayLengthsMismatch());
        for(uint256 i = 0; i < rtMrXCount; ++i){
            if(rtMrX[i] < totalValidRtMrCount){
                validRtMrHashes[rtMrX[i]][hashes[i]] = false;
            }
        }
        emit RtMrHashesUpdated(rtMrX, hashes, false);
    }  

    /**
     * @notice Validates a TD10 report body by checking its hashes.
     * @param report The TD10 report body to validate.
     * @return err The error code, or NoError if the report is valid.
     */
    function validateTD10ReportBody(TD10ReportBody calldata report) external view returns(TD10ReportError err) {
        if (!validTD10MrTDHashes[report.mrTd]) return TD10ReportError.InvalidMrTd;
        if (!validRtMrHashes[0][report.rtMr0]) return TD10ReportError.InvalidRtMr0;
        if (!validRtMrHashes[1][report.rtMr1]) return TD10ReportError.InvalidRtMr1;
        if (!validRtMrHashes[2][report.rtMr2]) return TD10ReportError.InvalidRtMr2;
        if (!validRtMrHashes[3][report.rtMr3]) return TD10ReportError.InvalidRtMr3;
        return TD10ReportError.NoError;
    }
    // match the entire set
}
