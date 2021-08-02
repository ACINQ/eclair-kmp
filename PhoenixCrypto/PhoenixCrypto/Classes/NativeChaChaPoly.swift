import Foundation
import CryptoKit
import os.log

fileprivate var log = Logger(
	subsystem: Bundle.main.bundleIdentifier!,
	category: "NativeChaChaPoly"
)

@objc
public class NativeChaChaPoly: NSObject {
	
	@objc
	public class func encrypt(
		key: Data,
		nonce: Data,
		authenticatedData: Data,
		plaintext: Data
	) -> Data {
	
		// key.count must be 256 bits (32 bytes)
		let symKey = SymmetricKey(data: key)
	
		let chaNonce: ChaChaPoly.Nonce
		do {
			chaNonce = try ChaChaPoly.Nonce(data: nonce)
		} catch {
			// nonce must be 96 bits (12 bytes)
			log.error("ChaChaPoly.Nonce(): error: \(String(describing: error))")
			return Data()
		}
	
		let sealedBox: ChaChaPoly.SealedBox
		do {
			sealedBox = try ChaChaPoly.seal( plaintext,
			                          using: symKey,
			                          nonce: chaNonce,
			                 authenticating: authenticatedData)
		} catch {
			log.error("ChaChaPoly.seal(): error: \(String(describing: error))")
			return Data()
		}
		
		let result = sealedBox.ciphertext + sealedBox.tag
		return result
	}

	@objc
	public class func decrypt(
		key: Data,
		nonce: Data,
		authenticatedData: Data,
		ciphertextAndTag: Data
	) -> Data {
	
		if ciphertextAndTag.count < 16 {
			return Data()
		}
		
		let tagIndex = ciphertextAndTag.endIndex - 16
		
		let ciphertext = ciphertextAndTag[ciphertextAndTag.startIndex ..< tagIndex]
		let tag = ciphertextAndTag[tagIndex ..< ciphertextAndTag.endIndex]
		
		let symKey = SymmetricKey(data: key)
	
		let chaNonce: ChaChaPoly.Nonce
		do {
			chaNonce = try ChaChaPoly.Nonce(data: nonce)
		} catch {
			log.error("ChaChaPoly.Nonce(): error: \(String(describing: error))")
			return Data()
		}
	
		let sealedBox: ChaChaPoly.SealedBox
		do {
			sealedBox = try ChaChaPoly.SealedBox(
				nonce      : chaNonce,
				ciphertext : ciphertext,
				tag        : tag
			)
		} catch {
			log.error("ChaChaPoly.SealedBox(): error: \(String(describing: error))")
			return Data()
		}
	
		let plaintext: Data
		do {
			plaintext = try ChaChaPoly.open( sealedBox,
			                          using: symKey,
			                 authenticating: authenticatedData)
		} catch {
			log.error("ChaChaPoly.open(): error: \(String(describing: error))")
			return Data()
		}
	
		return plaintext
	}
}



