// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {HonkVerifier, IVerifier} from "../src/HonkVerifier.sol";
import {AnnouncementRegistry} from "../src/AnnouncementRegistry.sol";

/// End-to-end: real announcements, real proofs from `mfreg prove`, the generated verifier.
contract AnnouncementRegistryTest is Test {
    IVerifier verifier;

    struct Submission {
        bytes text;
        uint64 number;
        bytes20[2] signers;
        uint64 expiresAt;
        bytes proof;
        bytes32[] publicInputs;
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
        s.signers[0] = bytes20(vm.parseJsonBytes(json, ".signers[0]"));
        s.signers[1] = bytes20(vm.parseJsonBytes(json, ".signers[1]"));
        s.expiresAt = uint64(vm.parseJsonUint(json, ".expiresAt"));
        s.proof = vm.parseJsonBytes(json, ".proof");
        s.publicInputs = vm.parseJsonBytes32Array(json, ".publicInputs");
    }

    function submit(AnnouncementRegistry registry, Submission memory s) internal {
        registry.submit(s.text, s.number, s.signers, s.expiresAt, s.proof);
    }

    function foundation() internal returns (AnnouncementRegistry) {
        return new AnnouncementRegistry(verifier, keys("foundation"));
    }

    function test_KeySetMatchesPublishedFingerprints() public {
        bytes20[] memory set = foundation().keySet();
        assertEq(set.length, 5);
        assertEq(set[0], bytes20(hex"B26F10A7157EA66528FD21381CD1328B3352B251")); // signer_1
        assertEq(set[1], bytes20(hex"EE7A445EC4643BCEC07E76982E22B777D5136DBD")); // signer_2
        assertEq(set[2], bytes20(hex"53E38FB05A545B69C2C284EA27C4446634EC4967")); // signer_3
        assertEq(set[3], bytes20(hex"A74F880CF4910EC8A54AADDADFCF19E737660B35")); // signer_4
        assertEq(set[4], bytes20(hex"C63CAE08321029D52ACCD85CF8AEB590EB6069FB")); // signer_6
    }

    /// The contract must build exactly the public inputs the prover used.
    function test_PublicInputsMatchProver() public {
        AnnouncementRegistry registry = foundation();
        for (uint256 n = 0; n <= 6; n++) {
            Submission memory s = load(string.concat("mf-", vm.toString(n)));
            assertEq(registry.publicInputs(s.text, s.number, s.signers, s.expiresAt), s.publicInputs);
        }
    }

    function test_AllPublishedAnnouncements() public {
        AnnouncementRegistry registry = foundation();
        for (uint256 n = 0; n <= 6; n++) {
            Submission memory s = load(string.concat("mf-", vm.toString(n)));
            assertEq(s.number, n);
            uint256 gas = gasleft();
            submit(registry, s);
            console.log("mf-%d submit gas: %d", n, gas - gasleft());

            (string memory text, bytes20[] memory signers) = registry.announcement(uint64(n));
            assertEq(bytes(text), s.text);
            assertEq(signers[0], s.signers[0]);
            assertEq(signers[1], s.signers[1]);
        }
        assertEq(registry.count(), 7);
        assertEq(registry.latest(), 6);
    }

    function test_Sha256AndSha512Signatures() public {
        AnnouncementRegistry registry = new AnnouncementRegistry(verifier, keys("generated"));
        submit(registry, load("generated/sha"));
        assertEq(registry.count(), 1);
    }

    function test_ExpiredSignaturesAreRejected() public {
        Submission memory s = load("generated/expiring");
        assertEq(s.expiresAt, 1_790_000_000 + 10 * 365 days);

        AnnouncementRegistry registry = new AnnouncementRegistry(verifier, keys("generated"));
        vm.warp(s.expiresAt);
        vm.expectRevert(AnnouncementRegistry.SignatureExpired.selector);
        submit(registry, s);

        vm.warp(s.expiresAt - 1);
        submit(registry, s);
    }

    function test_RevertWhen_TextTampered() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        s.text[s.text.length - 2] = "X";
        vm.expectRevert();
        submit(registry, s);
    }

    function test_RevertWhen_OutputsDiffer() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");

        s.number = 7;
        vm.expectRevert();
        submit(registry, s);

        s = load("mf-6");
        (s.signers[0], s.signers[1]) = (s.signers[1], s.signers[0]);
        vm.expectRevert();
        submit(registry, s);

        s = load("generated/expiring");
        AnnouncementRegistry generated = new AnnouncementRegistry(verifier, keys("generated"));
        s.expiresAt = 0;
        vm.expectRevert();
        submit(generated, s);
    }

    function test_RevertWhen_ProofIsForAnotherAnnouncement() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        s.proof = load("mf-5").proof;
        vm.expectRevert();
        submit(registry, s);
    }

    function test_RevertWhen_KeySetDiffers() public {
        bytes[] memory all = keys("foundation");
        bytes[] memory withoutSigner3 = new bytes[](4);
        (withoutSigner3[0], withoutSigner3[1], withoutSigner3[2], withoutSigner3[3]) = (all[0], all[1], all[3], all[4]);
        AnnouncementRegistry registry = new AnnouncementRegistry(verifier, withoutSigner3);
        vm.expectRevert();
        submit(registry, load("mf-6"));
    }

    function test_RevertWhen_Duplicate() public {
        AnnouncementRegistry registry = foundation();
        submit(registry, load("mf-6"));
        vm.expectRevert(abi.encodeWithSelector(AnnouncementRegistry.AlreadyAnnounced.selector, 6));
        submit(registry, load("mf-6"));
    }

    function test_RevertWhen_TextTooLong() public {
        AnnouncementRegistry registry = foundation();
        Submission memory s = load("mf-6");
        s.text = new bytes(4097);
        vm.expectRevert(AnnouncementRegistry.TextTooLong.selector);
        submit(registry, s);
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
