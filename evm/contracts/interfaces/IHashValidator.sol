// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {TD10ReportBody} from "../types/V4Structs.sol";
enum TD10ReportError{
    NoError,
    InvalidMrTd,
    InvalidRtMr0,
    InvalidRtMr1,
    InvalidRtMr2,
    InvalidRtMr3
}
/**
 * @title IEnclaveHashValidator
 * @notice Interface for managing valid enclave hashes.
 */
interface IHashValidator {
    function addValidEnclaveHashes(bytes32[] calldata hashes) external;
    function removeValidEnclaveHashes(bytes32[] calldata hashes) external;
    function isValidEnclaveHash(bytes32 hash) external view returns (bool);
    function addValidTD10MrTDHashes(bytes[] calldata hashes) external;
    function removeValidTD10MrTDHashes(bytes[] calldata hashes) external;
    function isValidTD10MrTDHash(bytes calldata hash) external view returns(bool);
    function addValidRtMrHashes(uint256[] calldata rtMrX, bytes[] calldata hashes) external;
    function removeValidRtMrHashes(uint256[] calldata rtMrX, bytes[] calldata hashes) external;
    function validateTD10ReportBody(TD10ReportBody calldata report) external view returns(TD10ReportError);
}