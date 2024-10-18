//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

/// A lattice-based digital signature algorithm that provides security against quantum computing attacks.
public enum MLDSA {}

extension MLDSA {
    /// A ML-DSA-65 private key.
    public struct PrivateKey: Sendable {
        private var backing: Backing

        /// Initialize a ML-DSA-65 private key from a random seed.
        public init() throws {
            self.backing = try Backing()
        }

        /// Initialize a ML-DSA-65 private key from a seed.
        /// 
        /// The seed must be at least 32 bytes long.
        /// Any additional bytes in the seed are ignored.
        /// 
        /// - Parameter seed: The seed to use to generate the private key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not at least 32 bytes long.
        public init(seed: some DataProtocol) throws {
            self.backing = try Backing(seed: seed)
        }

        /// Initialize a ML-DSA-65 private key from a DER representation.
        /// 
        /// - Parameter derRepresentation: The DER representation of the private key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the DER representation is not the correct size.
        public init(derRepresentation: some DataProtocol) throws {
            self.backing = try Backing(derRepresentation: derRepresentation)
        }

        /// Initialize a ML-DSA-65 private key from a PEM representation.
        /// 
        /// - Parameter pemRepresentation: The PEM representation of the private key.
        public init(pemRepresentation: String) throws {
            self.backing = try Backing(pemRepresentation: pemRepresentation)
        }

        /// The public key associated with this private key.
        public var publicKey: PublicKey {
            self.backing.publicKey
        }

        /// Generate a signature for the given data.
        /// 
        /// - Parameters: 
        ///   - data: The message to sign.
        ///   - context: The context to use for the signature.
        /// 
        /// - Returns: The signature of the message.
        public func signature<D: DataProtocol>(for data: D, context: D? = nil) throws -> Signature {
            try self.backing.signature(for: data, context: context)
        }

        /// The size of the private key in bytes.
        static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            let pointer: UnsafeMutablePointer<MLDSA65_private_key>

            /// Initialize a ML-DSA-65 private key from a random seed.
            init() throws {
                self.pointer = UnsafeMutablePointer<MLDSA65_private_key>.allocate(capacity: 1)

                try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: MLDSA.PublicKey.Backing.bytesCount) { publicKeyPtr in
                    try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: MLDSA.seedSizeInBytes) { seedPtr in
                        guard CCryptoBoringSSL_MLDSA65_generate_key(
                            publicKeyPtr.baseAddress,
                            seedPtr.baseAddress,
                            self.pointer
                        ) == 1 else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                    }
                }
            }

            /// Initialize a ML-DSA-65 private key from a seed.
            /// 
            /// The seed must be at least 32 bytes long.
            /// Any additional bytes in the seed are ignored.
            /// 
            /// - Parameter seed: The seed to use to generate the private key.
            /// 
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not at least 32 bytes long.
            init(seed: some DataProtocol) throws {
                guard seed.count >= MLDSA.seedSizeInBytes else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.pointer = UnsafeMutablePointer<MLDSA65_private_key>.allocate(capacity: 1)

                guard CCryptoBoringSSL_MLDSA65_private_key_from_seed(
                    self.pointer,
                    Array(seed.prefix(MLDSA.seedSizeInBytes)),
                    MLDSA.seedSizeInBytes
                ) == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }

            /// Initialize a ML-DSA-65 private key from a DER representation.
            /// 
            /// - Parameter derRepresentation: The DER representation of the private key.
            /// 
            /// - Throws: `CryptoKitError.incorrectKeySize` if the DER representation is not the correct size.
            init(derRepresentation: some DataProtocol) throws {
                guard derRepresentation.count == MLDSA.PrivateKey.Backing.bytesCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.pointer = UnsafeMutablePointer<MLDSA65_private_key>.allocate(capacity: 1)

                try derRepresentation.regions.flatMap { $0 }.withUnsafeBufferPointer { buffer in
                    let cbsPointer = UnsafeMutablePointer<CBS>.allocate(capacity: 1)
                    defer { cbsPointer.deallocate() }
                    cbsPointer.pointee = CBS(data: buffer.baseAddress, len: buffer.count)

                    guard CCryptoBoringSSL_MLDSA65_parse_private_key(self.pointer, cbsPointer) == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                }
            }

            /// Initialize a ML-DSA-65 private key from a PEM representation.
            /// 
            /// - Parameter pemRepresentation: The PEM representation of the private key.
            convenience init(pemRepresentation: String) throws {
                let document = try ASN1.PEMDocument(pemString: pemRepresentation)
                try self.init(derRepresentation: document.derBytes)
            }

            /// The public key associated with this private key.
            var publicKey: PublicKey {
                PublicKey(privateKeyBacking: self)
            }

            /// Generate a signature for the given data.
            /// 
            /// - Parameters: 
            ///   - data: The message to sign.
            ///   - context: The context to use for the signature.
            /// 
            /// - Returns: The signature of the message.
            func signature<D: DataProtocol>(for data: D, context: D? = nil) throws -> Signature {
                let output = try Array<UInt8>(unsafeUninitializedCapacity: Signature.bytesCount) { bufferPtr, length in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    let result = bytes.withUnsafeBytes { dataPtr in
                        if let context {
                            CCryptoBoringSSL_MLDSA65_sign(
                                bufferPtr.baseAddress,
                                self.pointer,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                Array(context),
                                context.count
                            )
                        } else {
                            CCryptoBoringSSL_MLDSA65_sign(
                                bufferPtr.baseAddress,
                                self.pointer,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                nil,
                                0
                            )
                        }
                    }

                    guard result == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    length = Signature.bytesCount
                }
                return Signature(signatureBytes: output)
            }

            /// The size of the private key in bytes.
            static let bytesCount = 4032
        }
    }
}

extension MLDSA {
    /// A ML-DSA-65 public key.
    public struct PublicKey: Sendable {
        private var backing: Backing

        fileprivate init(privateKeyBacking: PrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        /// Initialize a ML-DSA-65 public key from a DER representation.
        /// 
        /// - Parameter derRepresentation: The DER representation of the public key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the DER representation is not the correct size.
        public init(derRepresentation: some DataProtocol) throws {
            self.backing = try Backing(derRepresentation: derRepresentation)
        }

        /// Initialize a ML-DSA-65 public key from a PEM representation.
        /// 
        /// - Parameter pemRepresentation: The PEM representation of the public key.
        public init(pemRepresentation: String) throws {
            self.backing = try Backing(pemRepresentation: pemRepresentation)
        }

        /// The DER representation of the public key.
        public var derRepresentation: Data {
            get throws {
                try self.backing.derRepresentation
            }
        }

        /// The PEM representation of the public key.
        public var pemRepresentation: String {
            get throws {
                try self.backing.pemRepresentation
            }
        }

        /// Verify a signature for the given data.
        /// 
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///   - context: The context to use for the signature verification.
        /// 
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D, context: D? = nil) -> Bool {
            self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// The size of the public key in bytes.
        static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            private let pointer: UnsafeMutablePointer<MLDSA65_public_key>

            init(privateKeyBacking: PrivateKey.Backing) {
                self.pointer = UnsafeMutablePointer<MLDSA65_public_key>.allocate(capacity: 1)
                CCryptoBoringSSL_MLDSA65_public_from_private(self.pointer, privateKeyBacking.pointer)
            }

            /// Initialize a ML-DSA-65 public key from a DER representation.
            /// 
            /// - Parameter derRepresentation: The DER representation of the public key.
            /// 
            /// - Throws: `CryptoKitError.incorrectKeySize` if the DER representation is not the correct size.
            init(derRepresentation: some DataProtocol) throws {
                guard derRepresentation.count == MLDSA.PublicKey.Backing.bytesCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.pointer = UnsafeMutablePointer<MLDSA65_public_key>.allocate(capacity: 1)

                try derRepresentation.regions.flatMap { $0 }.withUnsafeBufferPointer { buffer in
                    let cbsPointer = UnsafeMutablePointer<CBS>.allocate(capacity: 1)
                    defer { cbsPointer.deallocate() }
                    cbsPointer.pointee = CBS(data: buffer.baseAddress, len: buffer.count)

                    guard CCryptoBoringSSL_MLDSA65_parse_public_key(self.pointer, cbsPointer) == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                }
            }

            /// Initialize a ML-DSA-65 public key from a PEM representation.
            /// 
            /// - Parameter pemRepresentation: The PEM representation of the public key.
            convenience init(pemRepresentation: String) throws {
                let document = try ASN1.PEMDocument(pemString: pemRepresentation)
                try self.init(derRepresentation: document.derBytes)
            }

            /// The DER representation of the public key.
            var derRepresentation: Data {
                get throws {
                    var cbb = CBB()
                    // `CBB_init` can only return 0 on allocation failure, which we define as impossible.
                    CCryptoBoringSSL_CBB_init(&cbb, MLDSA.PublicKey.Backing.bytesCount)

                    guard CCryptoBoringSSL_MLDSA65_marshal_public_key(&cbb, self.pointer) == 1 else {
                        CCryptoBoringSSL_CBB_cleanup(&cbb)
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    guard let data = CCryptoBoringSSL_CBB_data(&cbb) else {
                        CCryptoBoringSSL_CBB_cleanup(&cbb)
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    return Data(bytes: data, count: CCryptoBoringSSL_CBB_len(&cbb))
                }
            }

            /// The PEM representation of the public key.
            var pemRepresentation: String {
                get throws {
                    ASN1.PEMDocument(type: MLDSA.PublicKeyType, derBytes: try self.derRepresentation).pemString
                }
            }

            /// Verify a signature for the given data.
            /// 
            /// - Parameters:
            ///   - signature: The signature to verify.
            ///   - data: The message to verify the signature against.
            ///   - context: The context to use for the signature verification.
            /// 
            /// - Returns: `true` if the signature is valid, `false` otherwise.
            func isValidSignature<D: DataProtocol>(_ signature: Signature, for data: D, context: D? = nil) -> Bool {
                signature.withUnsafeBytes { signaturePtr in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    let rc: CInt = bytes.withUnsafeBytes { dataPtr in
                        if let context {
                            CCryptoBoringSSL_MLDSA65_verify(
                                self.pointer,
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                Array(context),
                                context.count
                            )
                        } else {
                            CCryptoBoringSSL_MLDSA65_verify(
                                self.pointer,
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                nil,
                                0
                            )
                        }
                    }
                    return rc == 1
                }
            }

            /// The size of the public key in bytes.
            static let bytesCount = 1952
        }
    }
}

extension MLDSA {
    /// A ML-DSA-65 signature.
    public struct Signature: Sendable, ContiguousBytes {
        /// The raw binary representation of the signature.
        public var rawRepresentation: Data

        /// Initialize a ML-DSA-65 signature from a raw representation.
        /// 
        /// - Parameter rawRepresentation: The signature bytes.
        public init(rawRepresentation: some DataProtocol) {
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// Initialize a ML-DSA-65 signature from a raw representation.
        /// 
        /// - Parameter signatureBytes: The signature bytes.
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
        fileprivate static let bytesCount = 3309
    }
}

extension MLDSA {
    /// The ASN.1 object identifiers for a private ML-DSA-65 key.
    private static let KeyType = "PRIVATE KEY"
    
    /// The ASN.1 object identifiers for a public ML-DSA-65 key.
    private static let PublicKeyType = "PUBLIC KEY"

    /// The size of the seed in bytes.
    private static let seedSizeInBytes = 32
}