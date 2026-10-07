// The key-protector kind: each vault's data key in a generic-password
// Keychain item, service "foca", account "foca:<vault>:<vault-id>".
//
// Under ad-hoc signing this is a plain item in the login keychain (design
// §5): an item gated by SecAccessControl needs an entitlement only a signed
// .app can carry. Touch ID is enforced by the authenticator, not the item.
// The item's ACL trusts the program that created it, so other programs get
// the system's "allow access" prompt.

import Foundation
import Security

enum KeyProtector {
    static let service = "foca"
    static let refPart = try! NSRegularExpression(pattern: "^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")

    static func valid(_ s: String) -> Bool {
        refPart.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    static func run() -> Never {
        oneShot { req in
            let p = req.params
            try p.only(["vault", "vault_id", "dek", "sealed"])
            let vault = try p.string("vault")
            let vaultID = try p.string("vault_id")
            guard valid(vault), valid(vaultID) else { throw Failure.badRequest("invalid vault or vault_id") }
            let account = "foca:\(vault):\(vaultID)"
            // The key slot names the entry it was sealed into. A slot that
            // names another vault's entry is refused, so an edited vault
            // header can't borrow another vault's key.
            let sealed = try p.data("sealed")
            if let s = sealed, s != Data(account.utf8) {
                throw Failure("mismatch", "the key slot names another vault's entry")
            }
            switch req.op {
            case "seal":
                guard var dek = try p.data("dek"), (1...64).contains(dek.count) else {
                    throw Failure.badRequest("dek must be 1..64 bytes")
                }
                defer { dek.resetBytes(in: 0..<dek.count) }
                try seal(vault: vault, account: account, dek: dek)
                return ["sealed": Data(account.utf8).base64EncodedString()]
            case "unseal":
                guard sealed != nil else { throw Failure.badRequest("sealed is required") }
                var dek = try unseal(account: account)
                defer { dek.resetBytes(in: 0..<dek.count) }
                return ["dek": dek.base64EncodedString()]
            case "destroy":
                try destroy(account: account)
                return [:]
            default:
                throw Failure.badRequest("unknown op \(req.op) for key-protector")
            }
        }
    }

    static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// Adds the item. An existing one is never overwritten.
    static func seal(vault: String, account: String, dek: Data) throws {
        var q = query(account)
        q[kSecAttrLabel as String] = "foca vault key (\(vault))"
        q[kSecAttrDescription as String] = "foca vault key"
        q[kSecAttrSynchronizable as String] = false
        q[kSecValueData as String] = dek
        let status = SecItemAdd(q as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw Failure("exists", account)
        default:
            throw failure(status)
        }
    }

    static func unseal(account: String) throws -> Data {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard let d = out as? Data, !d.isEmpty else { throw Failure("internal", "keychain item has no data") }
            return d
        case errSecItemNotFound:
            throw Failure("not_found", account)
        default:
            throw failure(status)
        }
    }

    /// Deletes the item; a missing one is fine.
    static func destroy(account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw failure(status)
        }
    }

    static func failure(_ status: OSStatus) -> Failure {
        let msg = (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
        switch status {
        case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled:
            // A locked keychain, or the user refused the access prompt.
            return Failure("unavailable", msg)
        default:
            return Failure("internal", "\(status): \(msg)")
        }
    }
}
