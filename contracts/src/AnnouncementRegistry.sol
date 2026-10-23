// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "./HonkVerifier.sol";
import {SHA1} from "./vendor/SHA1.sol";

/// @title AnnouncementRegistry
/// @notice Monad Foundation node-ops announcements with verified OpenPGP signatures.
///         Anyone can submit; nobody can change the rules.
/// @dev A Noir proof (circuit/) attests that the text carries valid signatures by
///      two distinct pinned keys, and yields the announcement number, the signers
///      and the earliest signature expiration. The contract only feeds the text and
///      the keys to the verifier, checks the expiration against the block time, and
///      stores the text. The key set and verifier are fixed: a new key set means a
///      new contract.
contract AnnouncementRegistry {
    struct Announcement {
        string text;
        bytes20[] signers;
    }

    /// @dev Must match the circuit's globals.
    uint256 public constant MAX_TEXT = 4096;
    uint256 internal constant TEXT_FIELDS = 133; // ceil(4096 / 31)
    uint256 internal constant MAX_KEYS = 8;
    uint256 internal constant INPUTS = TEXT_FIELDS + 1 + 3 * MAX_KEYS + 4;

    /// @notice Verifier of the circuit in circuit/.
    IVerifier public immutable verifier;

    /// @notice Number of announcements registered.
    uint64 public count;
    /// @notice Highest announcement number registered. Only meaningful when count > 0.
    uint64 public latest;

    bytes20[] private _fingerprints;
    /// @dev The circuit's key inputs: MAX_KEYS fingerprints, then MAX_KEYS public keys as 16-byte halves.
    bytes32[3 * MAX_KEYS] private _keyInputs;
    mapping(uint64 => Announcement) private _announcements;

    event Announced(uint64 indexed number);

    error UnsupportedKey();
    error DuplicateKey();
    error TooManyKeys();
    error TextTooLong();
    error AlreadyAnnounced(uint64 number);
    error SignatureExpired();
    error InvalidProof();
    error NotAnnounced(uint64 number);

    /// @param keyPackets OpenPGP v4 Ed25519 primary public key packet bodies.
    ///        Their fingerprints are computed here, so `keySet()` can be compared
    ///        directly with the fingerprints the Foundation publishes.
    constructor(IVerifier verifier_, bytes[] memory keyPackets) {
        if (keyPackets.length > MAX_KEYS) revert TooManyKeys();
        verifier = verifier_;
        for (uint256 i = 0; i < keyPackets.length; i++) {
            bytes memory packet = keyPackets[i];
            if (!_isEd25519Key(packet)) revert UnsupportedKey();
            bytes20 fingerprint = SHA1.sha1(abi.encodePacked(uint8(0x99), uint16(packet.length), packet));
            for (uint256 j = 0; j < i; j++) {
                if (_fingerprints[j] == fingerprint) revert DuplicateKey();
            }
            bytes32 publicKey;
            assembly {
                publicKey := mload(add(packet, 51)) // body[19..51]
            }
            _fingerprints.push(fingerprint);
            _keyInputs[i] = bytes32(uint256(uint160(fingerprint)));
            _keyInputs[MAX_KEYS + 2 * i] = bytes32(uint256(publicKey) >> 128);
            _keyInputs[MAX_KEYS + 2 * i + 1] = bytes32(uint256(uint128(uint256(publicKey))));
        }
    }

    /// @notice Registers an announcement.
    /// @param text announcement.txt as published.
    /// @param number, signers, expiresAt The circuit's outputs, as written by `mfreg prove`.
    /// @param proof The proof from `mfreg prove`.
    function submit(
        bytes calldata text,
        uint64 number,
        bytes20[2] calldata signers,
        uint64 expiresAt,
        bytes calldata proof
    ) external {
        Announcement storage a = _announcements[number];
        if (a.signers.length != 0) revert AlreadyAnnounced(number);
        if (expiresAt != 0 && block.timestamp >= expiresAt) revert SignatureExpired();
        if (!verifier.verify(proof, publicInputs(text, number, signers, expiresAt))) revert InvalidProof();

        a.text = string(text);
        a.signers.push(signers[0]);
        a.signers.push(signers[1]);
        if (count == 0 || number > latest) latest = number;
        count++;
        emit Announced(number);
    }

    /// @notice The circuit's public inputs for an announcement, in declaration order:
    ///         text (31-byte big-endian chunks), text length, key fingerprints, key
    ///         halves, then the outputs: number, both signers, expiration.
    function publicInputs(bytes calldata text, uint64 number, bytes20[2] calldata signers, uint64 expiresAt)
        public
        view
        returns (bytes32[] memory inputs)
    {
        if (text.length > MAX_TEXT) revert TextTooLong();
        inputs = new bytes32[](INPUTS);
        for (uint256 i = 0; i < TEXT_FIELDS; i++) {
            uint256 start = i * 31;
            if (start >= text.length) break;
            uint256 end = start + 31 < text.length ? start + 31 : text.length;
            // bytes32(slice) pads on the right; shifting by a byte aligns the 31-byte chunk.
            inputs[i] = bytes32(uint256(bytes32(text[start:end])) >> 8);
        }
        inputs[TEXT_FIELDS] = bytes32(text.length);
        for (uint256 i = 0; i < 3 * MAX_KEYS; i++) {
            inputs[TEXT_FIELDS + 1 + i] = _keyInputs[i];
        }
        uint256 o = TEXT_FIELDS + 1 + 3 * MAX_KEYS;
        inputs[o] = bytes32(uint256(number));
        inputs[o + 1] = bytes32(uint256(uint160(signers[0])));
        inputs[o + 2] = bytes32(uint256(uint160(signers[1])));
        inputs[o + 3] = bytes32(uint256(expiresAt));
    }

    /// @notice The verified text of announcement `number` and the fingerprints that signed it.
    function announcement(uint64 number) external view returns (string memory text, bytes20[] memory signers) {
        Announcement storage a = _announcements[number];
        if (a.signers.length == 0) revert NotAnnounced(number);
        return (a.text, a.signers);
    }

    /// @notice The pinned primary key fingerprints, as in gpg-keys.json.
    function keySet() external view returns (bytes20[] memory) {
        return _fingerprints;
    }

    /// @dev version 4, EdDSA (22), Ed25519 OID, 263-bit MPI with the 0x40 native prefix.
    function _isEd25519Key(bytes memory p) private pure returns (bool) {
        return p.length == 51 && p[0] == 0x04 && p[5] == 0x16 && p[6] == 0x09
            && keccak256(abi.encodePacked(p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]))
                == keccak256(hex"2b06010401da470f01") && p[16] == 0x01 && p[17] == 0x07 && p[18] == 0x40;
    }
}
