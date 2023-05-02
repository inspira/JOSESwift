import XCTest

@testable import JOSESwift


class AES128GCMEncryptionTests: XCTestCase {

    /// Tests the `AES` encryption implementation for A128GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).
    // Create the plaintext
    let expectedPlaintext = "Hello, world!".data(using: .utf8)!

    let contentEncryptionKey = Data([
        177, 161, 244, 128, 84, 143, 225, 115,
        63, 180, 3, 255, 107, 154, 212, 246
    ])
    
    let initializationVector = Data([
        227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219
    ])

    let additionalAuthenticatedDate = Data([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
        54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81
    ])

    let expectedCiphertext = Data([
        63, 121, 88, 140, 70, 27, 50, 12, 95, 38, 19, 40, 158
    ])

    let expectedAuthenticationTag = Data([
        36, 50, 20, 80, 66, 242, 32, 45, 37,
        184, 55, 239, 105, 175, 195, 50
    ])
    
    func testEncryptingA128GCM() throws {
        let encrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A128GCM, contentEncryptionKey: contentEncryptionKey)

        let symmetricEncryptionContext = try encrypter.encrypt(expectedPlaintext, initializationVector: initializationVector, additionalAuthenticatedData: additionalAuthenticatedDate)

        XCTAssertEqual(expectedCiphertext, symmetricEncryptionContext.ciphertext)
        XCTAssertEqual(expectedAuthenticationTag, symmetricEncryptionContext.authenticationTag)
    }


    /// Tests the `AES` decryption implementation for A128GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).
    func testDecryptingA128GCM() throws {

        let decrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A128GCM, contentEncryptionKey: contentEncryptionKey)

        let plaintext = try decrypter.decrypt(expectedCiphertext, initializationVector: initializationVector, additionalAuthenticatedData: additionalAuthenticatedDate, authenticationTag: expectedAuthenticationTag)

        XCTAssertEqual(expectedPlaintext, plaintext)

    }

}
