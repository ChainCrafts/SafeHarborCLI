// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {SafeHarborManifestRegistry} from "../src/SafeHarborManifestRegistry.sol";

interface Vm {
    function expectRevert(bytes4 selector) external;
    function prank(address sender) external;
}

contract SafeHarborManifestRegistryTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    SafeHarborManifestRegistry private registry;

    address private constant AGREEMENT = address(0x4A13d7c0b6E9F24c1d8a3E5b7f02c6d9a1e4B3F8);
    bytes32 private constant HASH_ONE = 0x674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb06;
    bytes32 private constant HASH_TWO = 0x8a4cb06674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c;

    function setUp() public {
        registry = new SafeHarborManifestRegistry();
    }

    function testPublishSuccess() public {
        registry.publish(AGREEMENT, HASH_ONE, "ipfs://manifest-one");

        SafeHarborManifestRegistry.Publication memory publication = registry.currentPublication(AGREEMENT);

        require(publication.agreement == AGREEMENT, "agreement mismatch");
        require(publication.manifestHash == HASH_ONE, "hash mismatch");
        require(keccak256(bytes(publication.manifestUri)) == keccak256(bytes("ipfs://manifest-one")), "uri mismatch");
        require(publication.publisher == address(this), "publisher mismatch");
        require(publication.publishedAt == uint64(block.timestamp), "timestamp mismatch");
    }

    function testOverwriteUpdatesCurrentPublication() public {
        registry.publish(AGREEMENT, HASH_ONE, "ipfs://manifest-one");
        registry.publish(AGREEMENT, HASH_TWO, "ipfs://manifest-two");

        SafeHarborManifestRegistry.Publication memory publication = registry.currentPublication(AGREEMENT);

        require(publication.manifestHash == HASH_TWO, "hash not overwritten");
        require(
            keccak256(bytes(publication.manifestUri)) == keccak256(bytes("ipfs://manifest-two")), "uri not overwritten"
        );
    }

    function testZeroAgreementRejected() public {
        vm.expectRevert(SafeHarborManifestRegistry.ZeroAgreement.selector);
        registry.publish(address(0), HASH_ONE, "ipfs://manifest-one");
    }

    function testZeroManifestHashRejected() public {
        vm.expectRevert(SafeHarborManifestRegistry.ZeroManifestHash.selector);
        registry.publish(AGREEMENT, bytes32(0), "ipfs://manifest-one");
    }

    function testEmptyManifestUriRejected() public {
        vm.expectRevert(SafeHarborManifestRegistry.EmptyManifestUri.selector);
        registry.publish(AGREEMENT, HASH_ONE, "");
    }

    function testUnauthorizedPublisherRejected() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(SafeHarborManifestRegistry.Unauthorized.selector);
        registry.publish(AGREEMENT, HASH_ONE, "ipfs://manifest-one");
    }
}
