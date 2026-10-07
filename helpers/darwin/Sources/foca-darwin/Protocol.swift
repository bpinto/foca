// Helper protocol v1 (foca design §5). One-shot kinds read one JSON request
// on stdin and write one JSON response on stdout; logs go to stderr.
//
//   stdin : {"v":1,"op":"approve","params":{…}}
//   stdout: {"v":1,"ok":true,"result":{…}}
//        or {"v":1,"ok":false,"error":{"code":"denied","message":"…"}}

import Foundation

let protocolVersion = 1
let helperVersion = "0.1.0"
let maxRequest = 1 << 20

/// An error answer. The code is one the Go adapter knows.
struct Failure: Error {
    let code: String
    let message: String

    init(_ code: String, _ message: String = "") {
        self.code = code
        self.message = message
    }

    static func badRequest(_ message: String) -> Failure { Failure("bad_request", message) }
}

/// Typed, strict access to a request's params.
struct Params {
    let dict: [String: Any]

    /// Refuses any key outside keys: a field the helper doesn't know might
    /// be one the caller relies on.
    func only(_ keys: Set<String>) throws {
        for k in dict.keys where !keys.contains(k) {
            throw Failure.badRequest("unknown param \(k)")
        }
    }

    func string(_ key: String) throws -> String {
        guard let s = dict[key] as? String else { throw Failure.badRequest("\(key) must be a string") }
        return s
    }

    func bool(_ key: String) throws -> Bool {
        guard let v = dict[key] else { return false }
        guard let n = v as? NSNumber, isBool(n) else { throw Failure.badRequest("\(key) must be a boolean") }
        return n.boolValue
    }

    func int(_ key: String) throws -> Int {
        guard let n = dict[key] as? NSNumber, !isBool(n) else { throw Failure.badRequest("\(key) must be a number") }
        return n.intValue
    }

    /// Base64 bytes, or nil when the key is absent.
    func data(_ key: String) throws -> Data? {
        guard let v = dict[key] else { return nil }
        guard let s = v as? String, let d = Data(base64Encoded: s) else { throw Failure.badRequest("\(key) must be base64") }
        return d
    }
}

func isBool(_ n: NSNumber) -> Bool { CFGetTypeID(n) == CFBooleanGetTypeID() }

struct Request {
    let op: String
    let params: Params
}

func parseRequest(_ data: Data) throws -> Request {
    guard let obj = try? JSONSerialization.jsonObject(with: data), let dict = obj as? [String: Any] else {
        throw Failure.badRequest("malformed request")
    }
    for k in dict.keys where !["v", "op", "params"].contains(k) {
        throw Failure.badRequest("unknown field \(k)")
    }
    guard let v = dict["v"] as? NSNumber, !isBool(v), v.intValue == protocolVersion else {
        throw Failure.badRequest("protocol version \(dict["v"] ?? "none") is not supported (want \(protocolVersion))")
    }
    guard let op = dict["op"] as? String else { throw Failure.badRequest("op must be a string") }
    var params: [String: Any] = [:]
    if let p = dict["params"] {
        guard let d = p as? [String: Any] else { throw Failure.badRequest("params must be an object") }
        params = d
    }
    return Request(op: op, params: Params(dict: params))
}

/// Reads the whole of stdin: the Go side closes it after the request.
func readRequest() throws -> Request {
    var data = Data()
    while true {
        let chunk = FileHandle.standardInput.availableData
        if chunk.isEmpty { break }
        data.append(chunk)
        if data.count > maxRequest { throw Failure.badRequest("request too large") }
    }
    defer { data.resetBytes(in: 0..<data.count) }
    return try parseRequest(data)
}

/// Writes one JSON line to stdout with write(2), so a closed pipe ends the
/// process instead of raising an Objective-C exception.
func writeLine(_ obj: [String: Any]) {
    guard var data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]) else {
        log("can't encode a response")
        exit(1)
    }
    data.append(0x0A)
    defer { data.resetBytes(in: 0..<data.count) }
    data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
        var off = 0
        while off < buf.count {
            let n = write(1, buf.baseAddress! + off, buf.count - off)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { exit(1) }
            off += n
        }
    }
}

func respond(_ result: [String: Any]) -> Never {
    writeLine(["v": protocolVersion, "ok": true, "result": result])
    exit(0)
}

func fail(_ f: Failure) -> Never {
    writeLine(["v": protocolVersion, "ok": false, "error": ["code": f.code, "message": f.message]])
    exit(1)
}

/// Runs a synchronous one-shot kind.
func oneShot(_ handle: (Request) throws -> [String: Any]) -> Never {
    do {
        let req = try readRequest()
        respond(try handle(req))
    } catch let f as Failure {
        fail(f)
    } catch {
        fail(Failure("internal", "\(error)"))
    }
}

func log(_ message: String) {
    FileHandle.standardError.write(Data(("foca-darwin: " + message + "\n").utf8))
}
