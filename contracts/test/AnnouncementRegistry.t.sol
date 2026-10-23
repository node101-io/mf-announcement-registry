// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {HonkVerifier, IVerifier} from "../src/HonkVerifier.sol";
import {AnnouncementRegistry} from "../src/AnnouncementRegistry.sol";

/// End-to-end: real announcements, real proofs from `mfreg prove`, the generated verifier.
contract AnnouncementRegistryTest is Test {
    IVerifier verifier;

    struct Proof {
        bytes20 signer;
        uint64 expiresAt;
        bytes proof;
        bytes32[] publicInputs;
    }

    struct Submission {
        bytes text;
        uint64 number;
        Proof[2] proofs;
    }

    function setUp() public {
        verifier = new HonkVerifier();
    }

    function keys(string memory set) internal view returns (bytes[] memory packets) {
        string memory json = vm.readFile("test/fixtures/keys.json");
        string[] memory hexes = vm.split(vm.parseJsonString(json, string.concat(".", set)), ",");
        packets = new bytes[](hexes.length);
        for (uint256 i = 0; i < hexes.length; i++) {
            packets[i] = vm.parseBytes(hexes[i]);
        }
    }

    function load(string memory dir) internal view returns (Submission memory s) {
        string memory json = vm.readFile(string.concat("../testdata/", dir, "/proof.json"));
        s.text = vm.parseJsonBytes(json, ".text");
        s.number = uint64(vm.parseJsonUint(json, ".number"));
        for (uint256 i = 0; i < 2; i++) {
            string memory p = string.concat(".proofs[", vm.toString(i), "]");
            s.proofs[i].signer = bytes20(vm.parseJsonBytes(json, string.concat(p, ".signer")));
            s.proofs[i].expiresAt = uint64(vm.parseJsonUint(json, string.concat(p, ".expiresAt")));
            s.proofs[i].proof = vm.parseJsonBytes(json, string.concat(p, ".proof"));
            s.proofs[i].publicInputs = vm.parseJsonBytes32Array(json, string.concat(p, ".publicInputs"));
        }
    }

    function submit(AnnouncementRegistry registry, Submission memory s, uint256 i) internal {
        Proof memory p = s.proofs[i];
        registry.submit(s.text, s.number, p.signer, p.expiresAt, p.proof);
    }

    function foundation() internal returns (AnnouncementRegistry) {
        return new AnnouncementRegistry(verifier, keys("foundation"));
    }

    function test_KeySetMatchesPublishedFingerprints() public {
        AnnouncementRegistry registry = foundation();
        bytes20[] memory set = registry.keySet();
        assertEq(set.length, 5);
        assertEq(set[0], bytes20(hex"B26F10A7157EA66528FD21381CD1328B3352B251")); // signer_1
        assertEq(set[1], bytes20(hex"EE7A445EC4643BCEC07E76982E22B777D5136DBD")); // signer_2
        assertEq(set[2], bytes20(hex"53E38FB05A545B69C2C284EA27C4446634EC4967")); // signer_3
        assertEq(set[3], bytes20(hex"A74F880CF4910EC8A54AADDADFCF19E737660B35")); // signer_4
        assertEq(set[4], bytes20(hex"C63CAE08321029D52ACCD85CF8AEB590EB6069FB")); // signer_6

        bytes[] memory packets = keys("foundation");
        bytes32[] memory publicKeys = registry.publicKeys();
        assertEq(publicKeys.length, 5);
        for (uint256 i = 0; i < 5; i++) {
            bytes memory packet = packets[i];
            bytes32 key;
            assembly {
                key := mload(add(packet, 51)) // body[19..51]
            }
            assertEq(publicKeys[i], key);
        }
    }

    /// The contract must build exactly the public inputs the prover used.
    function test_PublicInputsMatchProver() public {
        AnnouncementRegistry registry = foundation();
        for (uint256 n = 0; n <= 6; n++) {
            Submission memory s = load(string.concat("mf-", vm.toString(n)));
            for (uint256 i = 0; i < 2; i++) {
                Proof memory p = s.proofs[i];
                assertEq(registry.publicInputs(s.text, s.number, p.signer, p.expiresAt), p.publicInputs);
            }
        }
    }

    function test_AllPublishedAnnouncements() public {
        AnnouncementRegistry registry = foundation();
        for (uint256 n = 0; n <= 6; n++) {
            Submission memory s = load(string.concat("mf-", vm.toString(n)));
            assertEq(s.number, n);

            uint256 gas = gasleft();
            submit(registry, s, 0);
            console.log("mf-%d first signature gas: %d", n, gas - gasleft());
            vm.expectRevert(abi.encodeWithSelector(AnnouncementRegistry.NotAnnounced.selector, n));
            registry.announcement(uint64(n));
            assertEq(registry.pending(s.text).length, 1);
            assertEq(registry.pending(s.text)[0], s.proofs[0].signer);

            gas = gasleft();
            submit(registry, s, 1);
            console.log("mf-%d second signature gas: %d", n, gas - gasleft());
            (string memory text, bytes20[] memory signers) = registry.announcement(uint64(n));
            assertEq(bytes(text), s.text);
            assertEq(signers.length, 2);
            assertEq(signers[0], s.proofs[0].signer);
            assertEq(signers[1], s.proofs[1].signer);
            assertEq(registry.pending(s.text).length, 0);
        }
        assertEq(registry.count(), 7);
        assertEq(registry.latest(), 6);
    }

    function test_Sha256AndSha512Signatures() public {
        AnnouncementRegistry registry = new AnnouncementRegistry(verifier, keys("generated"));
        Submission memory s = load("generated/sha");
        submit(registry, s, 0);
        submit(registry, s, 1);
        assertEq(registry.count(), 1);
    }

    function test_ExpiredSignaturesAreRejected() public {
        Submission memory s = load("generated/expiring");
        uint256 i = s.proofs[0].expiresAt != 0 ? 0 : 1;
        assertEq(s.proofs[i].expiresAt, 1_790_000_000 + 10 * 365 days);
        assertEq(s.proofs[1 - i].expiresAt, 0);

        AnnouncementRegistry registry = new AnnouncementRegistry(verifier, keys("generated"));
        vm.warp(s.proofs[i].expiresAt);
        vm.expectRevert(AnnouncementRegistry.SignatureExpired.selector);
        submit(registry, s, i);

        vm.warp(s.proofs[i].expiresAt - 1);
        submit(registry, s, i);
    }

    function test_RevertWhen_SameSignerTwice() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        submit(registry, s, 0);
        vm.expectRevert(AnnouncementRegistry.AlreadySigned.selector);
        submit(registry, s, 0);
    }

    function test_SignaturesOfDifferentTextsDoNotCombine() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s6 = load("mf-6"); // signer_1, signer_2
        Submission memory s5 = load("mf-5"); // signer_2, signer_6
        submit(registry, s6, 0);
        submit(registry, s5, 1);
        assertEq(registry.count(), 0);
    }

    function test_RevertWhen_TextTampered() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        s.text[s.text.length - 2] = "X";
        vm.expectRevert();
        submit(registry, s, 0);
    }

    function test_RevertWhen_OutputsDiffer() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");

        s.number = 7;
        vm.expectRevert();
        submit(registry, s, 0);

        s = load("mf-6");
        s.proofs[0].signer = s.proofs[1].signer;
        vm.expectRevert();
        submit(registry, s, 0);

        s = load("generated/expiring");
        uint256 i = s.proofs[0].expiresAt != 0 ? 0 : 1;
        AnnouncementRegistry generated = new AnnouncementRegistry(verifier, keys("generated"));
        s.proofs[i].expiresAt = 0;
        vm.expectRevert();
        submit(generated, s, i);
    }

    function test_RevertWhen_ProofIsForAnotherAnnouncement() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        s.proofs[0].proof = load("mf-5").proofs[0].proof;
        vm.expectRevert();
        submit(registry, s, 0);
    }

    function test_RevertWhen_KeySetDiffers() public {
        bytes[] memory all = keys("foundation");
        bytes[] memory withoutSigner3 = new bytes[](4);
        (withoutSigner3[0], withoutSigner3[1], withoutSigner3[2], withoutSigner3[3]) = (all[0], all[1], all[3], all[4]);
        AnnouncementRegistry registry = new AnnouncementRegistry(verifier, withoutSigner3);
        vm.expectRevert();
        submit(registry, load("mf-6"), 0);
    }

    function test_RevertWhen_Duplicate() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        submit(registry, s, 0);
        submit(registry, s, 1);
        vm.expectRevert(abi.encodeWithSelector(AnnouncementRegistry.AlreadyAnnounced.selector, 6));
        submit(registry, s, 0);
    }

    function test_RevertWhen_TextTooLong() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        s.text = new bytes(4097);
        vm.expectRevert(AnnouncementRegistry.TextTooLong.selector);
        submit(registry, s, 0);
    }

    function test_RevertWhen_KeysInvalid() public {
        bytes[] memory all = keys("foundation");
        bytes[] memory twice = new bytes[](2);
        (twice[0], twice[1]) = (all[0], all[0]);
        vm.expectRevert(AnnouncementRegistry.DuplicateKey.selector);
        new AnnouncementRegistry(verifier, twice);

        bytes[] memory bad = new bytes[](1);
        bad[0] = all[0];
        bad[0][5] = 0x01; // RSA
        vm.expectRevert(AnnouncementRegistry.UnsupportedKey.selector);
        new AnnouncementRegistry(verifier, bad);

        vm.expectRevert(AnnouncementRegistry.TooManyKeys.selector);
        new AnnouncementRegistry(verifier, new bytes[](9));
    }

    function test_RevertWhen_NotAnnounced() public {
        AnnouncementRegistry registry = foundation();
        vm.expectRevert(abi.encodeWithSelector(AnnouncementRegistry.NotAnnounced.selector, 1));
        registry.announcement(1);
    }
}
