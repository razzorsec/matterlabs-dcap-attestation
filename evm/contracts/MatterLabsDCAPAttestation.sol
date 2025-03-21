pragma solidity ^0.8.27;
import "forge-std/Test.sol";

import {CA} from "@automata-network/on-chain-pccs/Common.sol";

import {
    EnclaveIdentityJsonObj,
    EnclaveIdentityHelper,
    IdentityObj
} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {TcbInfoJsonObj, FmspcTcbHelper} from "@automata-network/on-chain-pccs/helpers/FmspcTcbHelper.sol";
import {PCKHelper} from "@automata-network/on-chain-pccs/helpers/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helpers/X509CRLHelper.sol";

import {AutomataDaoStorage} from "@automata-network/on-chain-pccs/automata_pccs/shared/AutomataDaoStorage.sol";
import {AutomataPcsDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataPcsDao.sol";
import {AutomataPckDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataPckDao.sol";
import {AutomataEnclaveIdentityDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataEnclaveIdentityDao.sol";
import {AutomataFmspcTcbDao} from "@automata-network/on-chain-pccs/automata_pccs/AutomataFmspcTcbDao.sol";

import {PCCSRouter} from "./PCCSRouter.sol";
import {AttestationEntrypointBase} from "./AttestationEntrypointBase.sol";
import {HEADER_LENGTH, ENCLAVE_REPORT_LENGTH, SGX_TEE, TDX_TEE} from "./types/Constants.sol";
import {BELE} from "./utils/BELE.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import "./interfaces/IHashValidator.sol";
import {TD10ReportBody} from "./types/V4Structs.sol";

error InvalidP256Verifier();
error InvalidHashValidator();
error IncorrectVersion(uint256 version);
error IncorrectMrEnclave(bytes32 mrEnclave);
error VerificationFailed(bytes output);
error InvalidSigner(address recoveredSigner);
error InvalidTD10MrTd();
error InvalidTD10RtMr(uint8 rtMrX);
enum QuoteVerifierType{
    v3,
    v4
}

/**
 * @title MatterLabs DCAP Attestation
 * @dev Contract for handling attestation and verification using DCAP
 */
contract MatterLabsDCAPAttestation is AttestationEntrypointBase, Test{
    using ECDSA for bytes32;
    
    uint256 constant MR_ENCLAVE_OFFSET = HEADER_LENGTH + 64;
    uint256 constant ENCLAVE_REPORT_DATA_OFFSET = HEADER_LENGTH + 320;
    uint256 constant TD10_MRTD_OFFSET = HEADER_LENGTH + 136;
    uint256 constant TD10_RTMR0_OFFSET = HEADER_LENGTH + 328;
    uint256 constant TD10_RTMR1_OFFSET = TD10_RTMR0_OFFSET + 48;
    uint256 constant TD10_RTMR2_OFFSET = TD10_RTMR1_OFFSET + 48;
    uint256 constant TD10_RTMR3_OFFSET = TD10_RTMR2_OFFSET + 48;
    uint256 constant TD10_REPORT_DATA_OFFSET = HEADER_LENGTH + 520;
    uint8 constant RTMR_ENUM_ERROR_INDEX = 2;

    address P256_VERIFIER;
    EnclaveIdentityHelper public enclaveIdHelper;
    FmspcTcbHelper public tcbHelper;
    PCKHelper public x509;
    X509CRLHelper public x509Crl;

    AutomataDaoStorage pccsStorage;
    AutomataPcsDao pcsDao;
    AutomataPckDao pckDao;
    AutomataEnclaveIdentityDao enclaveIdDao;
    AutomataFmspcTcbDao fmspcTcbDao;

    PCCSRouter public pccsRouter;
    IHashValidator hashValidator;

    /**
     * @dev Initializes the contract with the P256 verifier and the Enclave Hash Validator and sets up dependencies.
     * @param _P256_Verifier Address of the P256 Verifier contract.
     * @param _hashValidator Address of the Enclave Hash Validator contract.
     */
    constructor(
        address _P256_Verifier,
        address _hashValidator
    ) {
        require(_P256_Verifier.code.length > 0, InvalidP256Verifier());
        P256_VERIFIER = _P256_Verifier;

        require(_hashValidator.code.length > 0, InvalidHashValidator());
        hashValidator = IHashValidator(_hashValidator);

        enclaveIdHelper = new EnclaveIdentityHelper();
        tcbHelper = new FmspcTcbHelper();
        x509 = new PCKHelper();
        x509Crl = new X509CRLHelper();

        pccsStorage = new AutomataDaoStorage();
        pcsDao = new AutomataPcsDao(address(pccsStorage), P256_VERIFIER, address(x509), address(x509Crl));
        pckDao =
            new AutomataPckDao(address(pccsStorage), P256_VERIFIER, address(pcsDao), address(x509), address(x509Crl));
        enclaveIdDao = new AutomataEnclaveIdentityDao(
            address(pccsStorage), P256_VERIFIER, address(pcsDao), address(enclaveIdHelper), address(x509)
        );
        fmspcTcbDao = new AutomataFmspcTcbDao(
            address(pccsStorage), P256_VERIFIER, address(pcsDao), address(tcbHelper), address(x509)
        );

        pccsStorage.updateDao(address(pcsDao), address(pckDao), address(enclaveIdDao), address(fmspcTcbDao));

        pccsRouter = new PCCSRouter(
            address(enclaveIdDao),
            address(fmspcTcbDao),
            address(pcsDao),
            address(pckDao),
            address(x509),
            address(x509Crl),
            address(tcbHelper)
        );
        pccsStorage.setCallerAuthorization(address(pccsRouter), true);
    }

    function verifyAndAttestOnChain(bytes calldata rawQuote, bytes32 digest, bytes calldata signature, QuoteVerifierType verifierType) external{
        (bool success, bytes memory output) = _verifyAndAttestOnChain(rawQuote);        
        require(success, VerificationFailed(output));

        bytes4 teeType = bytes4(uint32(BELE.leBytesToBeUint(rawQuote[4:8])));
        if (verifierType == QuoteVerifierType.v3 || teeType == SGX_TEE){
            _checkMrEnclave(rawQuote);
            uint256 reportDataOffset = ENCLAVE_REPORT_DATA_OFFSET;
            _checkSigner(rawQuote, digest, signature, reportDataOffset);
        }
        else if(teeType == TDX_TEE){
            _checkTD10Mr(rawQuote);
            uint256 reportDataOffset = TD10_REPORT_DATA_OFFSET;
            _checkSigner(rawQuote, digest, signature, reportDataOffset);
        }
    }

    function _checkMrEnclave(bytes calldata rawQuote) internal view{
        bytes32 mrEnclave = bytes32(rawQuote[MR_ENCLAVE_OFFSET: MR_ENCLAVE_OFFSET + 32]);
        require(hashValidator.isValidEnclaveHash(mrEnclave), IncorrectMrEnclave(mrEnclave));
    }

    function _checkSigner(bytes calldata rawQuote, bytes32 digest, bytes calldata signature, uint256 reportDataOffset) internal view{
        address signer = address(bytes20(rawQuote[reportDataOffset: reportDataOffset + 32]));
        uint256 version = uint256(bytes32(rawQuote[reportDataOffset + 32: reportDataOffset + 64]));
        require (version == 1, IncorrectVersion(version)); 
        address recovered = digest.recover(signature);
        require(recovered == signer, InvalidSigner(recovered));   
    }

    function _checkTD10Mr(bytes calldata rawQuote) internal view{
        TD10ReportBody memory report;
        report.mrTd = rawQuote[TD10_MRTD_OFFSET : TD10_MRTD_OFFSET + 48];
        report.rtMr0 = rawQuote[TD10_RTMR0_OFFSET : TD10_RTMR1_OFFSET];
        report.rtMr1 = rawQuote[TD10_RTMR1_OFFSET : TD10_RTMR2_OFFSET];
        report.rtMr2 = rawQuote[TD10_RTMR2_OFFSET : TD10_RTMR3_OFFSET];
        report.rtMr3 = rawQuote[TD10_RTMR3_OFFSET : TD10_RTMR3_OFFSET + 48];
        TD10ReportError errorType = hashValidator.validateTD10ReportBody(report);
        if (uint8(errorType) > 0){
            if (errorType == TD10ReportError.InvalidMrTd) revert InvalidTD10MrTd();
            revert InvalidTD10RtMr(uint8(errorType) - RTMR_ENUM_ERROR_INDEX);
        }
    }


    function updateP256Verifier(address _P256_VERIFIER) external onlyOwner{
        require(_P256_VERIFIER.code.length > 0, InvalidP256Verifier());
        P256_VERIFIER = _P256_VERIFIER;
    }

    function updateHashValidator(address _hashValidator) external onlyOwner{
        require(_hashValidator.code.length > 0, InvalidHashValidator());
        hashValidator = IHashValidator(_hashValidator);
    }


    // ============Functions to upsert Certificates to DAOs============

    function upsertPcsCertificates(CA ca, bytes calldata cert) external returns (bytes32 attestationId){
        attestationId = pcsDao.upsertPcsCertificates(ca, cert);
    }

    function upsertRootCACrl(bytes calldata rootcacrl) external returns (bytes32 attestationId){
        attestationId = pcsDao.upsertRootCACrl(rootcacrl);
    }

    function upsertPckCrl(CA ca, bytes calldata crl) external returns (bytes32 attestationId){
        attestationId = pcsDao.upsertPckCrl(ca, crl);
    }
    
    function upsertEnclaveIdentity(uint256 id, uint256 quoteVersion, EnclaveIdentityJsonObj calldata identityJson) external {
        enclaveIdDao.upsertEnclaveIdentity(id, quoteVersion, identityJson);
    }

    function upsertFmspcTcb(TcbInfoJsonObj calldata tcbInfoJson) external {
        fmspcTcbDao.upsertFmspcTcb(tcbInfoJson);
    }
    
    // ============Resolver Config Functions============


    function setResolverCallerAuthorization(address caller, bool authorized) external onlyOwner {
        pccsStorage.setCallerAuthorization(caller, authorized);
    }

    function pauseResolverCallerRestriction() external onlyOwner {
        pccsStorage.pauseCallerRestriction();
    }

    function unpauseResolverCallerRestriction() external onlyOwner {
        pccsStorage.unpauseCallerRestriction();
    }

    function updateResolverDao(address _pcsDao, address _pckDao, address _fmspcTcbDao, address _enclaveIdDao)
        external
        onlyOwner
    {
        pccsStorage.updateDao(_pcsDao, _pckDao, _fmspcTcbDao, _enclaveIdDao);
    }

    function revokeResolverDao(address revoked) external onlyOwner {
        pccsStorage.revokeDao(revoked);
    }

    // ============Router Config Functions============

    function setRouterAuthorization(address caller, bool authorized) external onlyOwner {
        pccsRouter.setAuthorized(caller, authorized);
    }

    function enableRouterCallerRestriction() external onlyOwner {
       pccsRouter.enableCallerRestriction();
    }

    function disableRouterCallerRestriction() external onlyOwner {
        pccsRouter.disableCallerRestriction();
    }

    function setRouterConfig(
        address _qeid, 
        address _fmspcTcb, 
        address _pcs, 
        address _pck,
        address _x509,
        address _x509Crl,
        address _tcbHelper
    ) external onlyOwner {
        pccsRouter.setConfig(_qeid, _fmspcTcb, _pcs, _pck, _x509, _x509Crl, _tcbHelper);
    }
}
