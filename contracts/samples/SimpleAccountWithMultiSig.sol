// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

import "../core/BaseAccount.sol";
import "./callback/TokenCallbackHandler.sol";

/**
  * minimal account.
  *  this is sample minimal account.
  *  has execute, eth handling methods
  *  has multisig that can send requests through the entryPoint.
  */
contract SimpleAccountWithMultiSig is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    mapping(address => bool) internal isOwner;
    uint256 threshold;
    bool canUpgrade;

    IEntryPoint private immutable _entryPoint;

    event SimpleAccountWithMultiSigInitialized(IEntryPoint indexed entryPoint, address[] owners, uint256 threshold);

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function _onlyMultiSig(bytes memory signature) internal view {
        // directly from multisig owner, or through the account itself (which gets redirected through execute())
        bytes32 hash = keccak256(abi.encode(getNonce()));
        require(
            isValidSignature(hash, signature) == IERC1271.isValidSignature.selector ||
            msg.sender == address(this),
            "only multisig"
        );
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPoint();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPoint();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    function executeWithMultiSig(address dest, uint256 value, bytes calldata func, bytes memory signature) external {
        _onlyMultiSig(signature);
        _call(dest, value, func);
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address[] calldata owners, uint256 _threshold) public virtual initializer {
        _initialize(owners, _threshold);
    }

    function _initialize(address[] calldata _owners, uint256 _threshold) internal virtual {
        uint256 ownerSize = _owners.length;
        for (uint256 i = 0; i < ownerSize; i++) {
            isOwner[_owners[i]] = true;
        }
        threshold = _threshold;
        emit SimpleAccountWithMultiSigInitialized(_entryPoint, _owners, _threshold);
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        if (isValidSignature(userOpHash, userOp.signature) != IERC1271.isValidSignature.selector)
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        public
        view
        returns (bytes4)
    {
        checkNSignatures(hash, signature, threshold);
        return IERC1271.isValidSignature.selector;
    }

    /// @dev divides bytes signature into `uint8 v, bytes32 r, bytes32 s`.
    /// @notice Make sure to perform a bounds check for @param pos, to avoid out of bounds access on @param signatures
    /// @param pos which signature to read. A prior bounds check of this parameter should be performed, to avoid out of bounds access
    /// @param signatures concatenated rsv signatures
    function signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (
            uint8 v,
            bytes32 r,
            bytes32 s
        )
    {
        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }

    /** 
         referece from gnosis safe validation
    **/
    function checkNSignatures(
        bytes32 dataHash,
        bytes memory signatures,
        uint256 requiredSignatures
    ) public view {
        // Check that the provided signature data is not too short
        require(
            signatures.length >= requiredSignatures * 65,
            "signatures too short"
        );
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            currentOwner = ecrecover(dataHash.toEthSignedMessageHash(), v, r, s);
            require(
                currentOwner > lastOwner && isOwner[currentOwner],
                "verify failed"
            );
            lastOwner = currentOwner;
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount, bytes memory signature) public {
        _onlyMultiSig(signature);
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function allowUpgrade(bytes memory signature) external {
        _onlyMultiSig(signature);
        canUpgrade = true;
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        (newImplementation);
        require(canUpgrade, "upgrade not allow");
        canUpgrade = false;
    }
}
