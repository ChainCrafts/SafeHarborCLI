// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Thin optional registry for associating BattleChain agreements with compiled SafeHarbor manifest pointers.
contract SafeHarborManifestRegistry {
    struct Publication {
        address agreement;
        bytes32 manifestHash;
        string manifestUri;
        address publisher;
        uint64 publishedAt;
    }

    error Unauthorized();
    error ZeroAgreement();
    error ZeroManifestHash();
    error EmptyManifestUri();

    event ManifestPublished(
        address indexed agreement,
        bytes32 indexed manifestHash,
        string manifestUri,
        address indexed publisher,
        uint64 publishedAt
    );

    address public immutable owner;

    mapping(address agreement => Publication publication) private publications;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    function publish(address agreement, bytes32 manifestHash, string calldata manifestUri) external onlyOwner {
        if (agreement == address(0)) {
            revert ZeroAgreement();
        }
        if (manifestHash == bytes32(0)) {
            revert ZeroManifestHash();
        }
        if (bytes(manifestUri).length == 0) {
            revert EmptyManifestUri();
        }

        uint64 publishedAt = uint64(block.timestamp);
        publications[agreement] = Publication({
            agreement: agreement,
            manifestHash: manifestHash,
            manifestUri: manifestUri,
            publisher: msg.sender,
            publishedAt: publishedAt
        });

        emit ManifestPublished(agreement, manifestHash, manifestUri, msg.sender, publishedAt);
    }

    function currentPublication(address agreement) external view returns (Publication memory) {
        return publications[agreement];
    }
}
