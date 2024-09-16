import XCTest

@testable import JOSESwift


class AES256GCMEncryptionTests: XCTestCase {

    /// Tests the `AES` encryption implementation for A256GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).

    let contentEncryptionKey = Data([
        177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246,
        138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252
    ])

    let expectedCiphertext = Data([
        229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
        233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
        104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
        123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
        160, 109, 64, 63, 192
    ])

    let initializationVector = Data([
        227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219
    ])

    let expectedPlaintext = Data([
        84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
        111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
        101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
        101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
        110, 97, 116, 105, 111, 110, 46
    ])
 
    let additionalAuthenticatedDate = Data([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
        54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81
    ])

    let expectedAuthenticationTag = Data([
        92, 80, 104, 49, 133, 25, 161, 215,
        173, 101, 219, 211, 136, 91, 210, 145
    ])

    func testEncryptingA256GCM() throws {

        let encrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A256GCM, contentEncryptionKey: contentEncryptionKey)

        let symmetricEncryptionContext = try encrypter.encrypt(expectedPlaintext, initializationVector: initializationVector, additionalAuthenticatedData: additionalAuthenticatedDate)

        XCTAssertEqual(expectedCiphertext, symmetricEncryptionContext.ciphertext)
        XCTAssertEqual(expectedAuthenticationTag, symmetricEncryptionContext.authenticationTag)

    }




    /// Tests the `AES` decryption implementation for A256GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).

    func testDecryptingA256GCM() throws {
        let decrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A256GCM, contentEncryptionKey: contentEncryptionKey)

        let plaintext = try decrypter.decrypt(expectedCiphertext, initializationVector: initializationVector, additionalAuthenticatedData: additionalAuthenticatedDate, authenticationTag: expectedAuthenticationTag)

        XCTAssertEqual(expectedPlaintext, plaintext)
    }

}
