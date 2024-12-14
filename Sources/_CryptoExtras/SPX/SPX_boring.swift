//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
import Crypto
import Foundation

/// The SPHINCS+-SHA2-128s digital signature algorithm, which provides security against quantum computing attacks.
public enum SPX {}

extension SPX {
    /// A SPHINCS+-SHA2-128s private key.
    public struct PrivateKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>

        /// Initialize a SPHINCS+-SHA2-128s private key from a random seed.
        public init() {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount)

            withUnsafeTemporaryAllocation(of: UInt8.self, capacity: SPX.PublicKey.bytesCount) { publicKeyPtr in
                CCryptoBoringSSL_SPX_generate_key(publicKeyPtr.baseAddress, self.pointer)
            }
        }

        // Initialize a SPHINCS+-SHA2-128s private key from a seed.
        ///
        /// - Parameter seed: The seed to use to generate the private key.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 48 bytes long.
        public init(seed: some DataProtocol) throws {
            guard seed.count == SPX.seedSizeInBytes else {
                throw CryptoKitError.incorrectKeySize
            }

            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount)

            withUnsafeTemporaryAllocation(of: UInt8.self, capacity: SPX.PublicKey.bytesCount) { publicKeyPtr in
                Data(seed).withUnsafeBytes { seedPtr in
                    CCryptoBoringSSL_SPX_generate_key_from_seed(
                        publicKeyPtr.baseAddress,
                        self.pointer,
                        seedPtr.baseAddress
                    )
                }
            }
        }

        /// Initialize a SPHINCS+-SHA2-128s private key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The private key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        public init(rawRepresentation: some DataProtocol) throws {
            guard rawRepresentation.count == SPX.PrivateKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PrivateKey.bytesCount)

            self.pointer.initialize(from: Array(rawRepresentation), count: SPX.PrivateKey.bytesCount)
        }

        /// The raw representation of the private key.
        public var rawRepresentation: Data {
            Data(UnsafeBufferPointer(start: self.pointer, count: SPX.PrivateKey.bytesCount))
        }

        /// The public key associated with this private key.
        public var publicKey: PublicKey {
            PublicKey(privateKeyBacking: self)
        }

        /// Generate a signature for the given data.
        ///
        /// - Parameters:
        ///   - data: The message to sign.
        ///   - randomized: Whether to randomize the signature.
        ///
        /// - Returns: The signature of the message.
        public func signature(for data: some DataProtocol, randomized: Bool = false) -> Signature {
            let output = [UInt8](unsafeUninitializedCapacity: Signature.bytesCount) { bufferPtr, length in
                let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                bytes.withUnsafeBytes { dataPtr in
                    CCryptoBoringSSL_SPX_sign(
                        bufferPtr.baseAddress,
                        self.pointer,
                        dataPtr.baseAddress,
                        dataPtr.count,
                        randomized ? 1 : 0
                    )
                }
                length = Signature.bytesCount
            }
            return Signature(signatureBytes: output)
        }

        /// The size of the private key in bytes.
        static let bytesCount = 64
    }
}

extension SPX {
    /// A SPHINCS+-SHA2-128s public key.
    public struct PublicKey: Sendable {
        private let pointer: UnsafeMutablePointer<UInt8>

        fileprivate init(privateKeyBacking: PrivateKey) {
            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount)
            self.pointer.initialize(
                from: privateKeyBacking.rawRepresentation.suffix(SPX.PublicKey.bytesCount),
                count: SPX.PublicKey.bytesCount
            )
        }

        /// Initialize a SPHINCS+-SHA2-128s public key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The public key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        public init(rawRepresentation: some DataProtocol) throws {
            guard rawRepresentation.count == SPX.PublicKey.bytesCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: SPX.PublicKey.bytesCount)

            self.pointer.initialize(from: Array(rawRepresentation), count: SPX.PublicKey.bytesCount)
        }

        /// The raw representation of the public key.
        public var rawRepresentation: Data {
            Data(UnsafeBufferPointer(start: self.pointer, count: SPX.PublicKey.bytesCount))
        }

        /// Verify a signature for the given data.
        ///
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D) -> Bool {
            signature.withUnsafeBytes { signaturePtr in
                let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                let rc: CInt = bytes.withUnsafeBytes { dataPtr in
                    return CCryptoBoringSSL_SPX_verify(
                        signaturePtr.baseAddress,
                        self.pointer,
                        dataPtr.baseAddress,
                        dataPtr.count
                    )
                }
                return rc == 1
            }
        }

        /// The size of the public key in bytes.
        static let bytesCount = 32
    }
}

extension SPX {
    /// A SPHINCS+-SHA2-128s signature.
    public struct Signature: Sendable, ContiguousBytes {
        /// The raw binary representation of the signature.
        public var rawRepresentation: Data

        /// Initialize a SPHINCS+-SHA2-128s signature from a raw representation.
        ///
        /// - Parameter rawRepresentation: The signature bytes.
        public init(rawRepresentation: some DataProtocol) {
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// Initialize a SPHINCS+-SHA2-128s signature from a raw representation.
        ///
        /// - Parameter rawRepresentation: The signature bytes.
        init(signatureBytes: [UInt8]) {
            self.rawRepresentation = Data(signatureBytes)
        }

        /// Access the signature bytes.
        ///
        /// - Parameter body: The closure to execute with the signature bytes.
        ///
        /// - Returns: The result of the closure.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// The size of the signature in bytes.
        static let bytesCount = 7856
    }
}

extension SPX {
    static let seedSizeInBytes = 3 * 16
}
