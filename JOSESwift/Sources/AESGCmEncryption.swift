//
//  AESGCmEncryption.swift
//  JOSESwift
//
//  Created by Swetha Sreekanth on 16/12/20.
//

import Foundation
import CryptoSwift
struct AESGCMEncryption {
    
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let contentEncryptionKey: Data
    
    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: Data) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.contentEncryptionKey = contentEncryptionKey
    }
    

    func encrypt(_ plaintext: Data, initializationVector: Data?, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        
        let iv = initializationVector == nil ?
            try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)
        : initializationVector!

        // Simplificação específica do 3DS SDK : criptografa em A128GCM somente o CReq
        // Idealmente deveria vir essa informação de quem chama a lib
        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey, direction: "left")
        let encryptionKey = keys.encryptionKey
        let  encryptTuple = try! CC.encryptAuth(blockMode: .gcm, algorithm:  .aes, data: plaintext, aData: additionalAuthenticatedData, key: encryptionKey, iv: iv, tagLength: 16)
        return ContentEncryptionContext(
            ciphertext: encryptTuple.0,
            authenticationTag: encryptTuple.1,
            initializationVector: iv
        )
    }

    func decrypt(
        _ ciphertext: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        guard contentEncryptionAlgorithm.checkKeyLength(for: contentEncryptionKey) else {
            throw JWEError.keyLengthNotSatisfied
        }
        // Simplificação específica do 3DS SDK : descriptografa em A128GCM somente o CRes
        // Idealmente deveria vir essa informação de quem chama a lib
        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey, direction: "right")
        let decryptionKey = keys.encryptionKey
        let plaintext = try! CC.decryptAuth(blockMode: .gcm, algorithm: .aes, data: ciphertext, aData: additionalAuthenticatedData, key: decryptionKey, iv: initializationVector, tagLength: 16)
        return plaintext
    }
}


extension AESGCMEncryption: ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext {
        let plaintext = payload.data()
        let additionalAuthenticatedData = header.data().base64URLEncodedData()
        return try encrypt(plaintext, initializationVector: nil, additionalAuthenticatedData: additionalAuthenticatedData)
        
    }
}

extension AESGCMEncryption: ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag
        )
    }
}
