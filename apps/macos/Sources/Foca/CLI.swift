import Foundation

/// Runs foca. Everything the app does is a host command the user could type
/// (design §8.7), so the app can never do more than the CLI.
struct FocaCLI {
    let path: String

    struct Result {
        let status: Int32
        let stdout: Data
        let stderr: String
    }

    /// Runs foca with args to the end, off the main thread.
    func run(_ args: [String]) async -> Result {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                cont.resume(returning: runSync(args))
            }
        }
    }

    private func runSync(_ args: [String]) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = out
        p.standardError = err
        do {
            try p.run()
        } catch {
            return Result(status: -1, stdout: Data(), stderr: error.localizedDescription)
        }
        // Both pipes are drained before waiting, so a full one can't stall
        // foca.
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            errData = err.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        p.waitUntilExit()
        return Result(status: p.terminationStatus, stdout: outData, stderr: String(decoding: errData, as: UTF8.self))
    }
}

/// A long-running `foca events follow`, handed over line by line on the main
/// queue.
final class Follower {
    private var process: Process?
    private var pending = Data()
    private var stderrTail = Data()
    private let tailLimit = 4096

    var isRunning: Bool { process?.isRunning ?? false }

    /// Starts foca with args. onLine gets each complete line; onExit the
    /// exit status and the end of stderr, unless stop() ended it.
    func start(_ cli: FocaCLI, _ args: [String], onLine: @escaping (Data) -> Void, onExit: @escaping (Int32, String) -> Void) {
        stop()
        pending = Data()
        stderrTail = Data()
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cli.path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = out
        p.standardError = err
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let chunk = h.availableData
            DispatchQueue.main.async {
                guard let self, self.process === p else { return }
                self.pending.append(chunk)
                while let nl = self.pending.firstIndex(of: UInt8(ascii: "\n")) {
                    let line = self.pending[self.pending.startIndex..<nl]
                    self.pending.removeSubrange(self.pending.startIndex...nl)
                    onLine(Data(line))
                }
            }
        }
        err.fileHandleForReading.readabilityHandler = { [weak self] h in
            let chunk = h.availableData
            DispatchQueue.main.async {
                guard let self, self.process === p else { return }
                self.stderrTail.append(chunk)
                if self.stderrTail.count > self.tailLimit {
                    self.stderrTail = self.stderrTail.suffix(self.tailLimit)
                }
            }
        }
        p.terminationHandler = { [weak self] p in
            out.fileHandleForReading.readabilityHandler = nil
            err.fileHandleForReading.readabilityHandler = nil
            let status = p.terminationStatus
            DispatchQueue.main.async {
                guard let self, self.process === p else { return }
                self.process = nil
                onExit(status, String(decoding: self.stderrTail, as: UTF8.self))
            }
        }
        process = p
        do {
            try p.run()
        } catch {
            process = nil
            onExit(-1, error.localizedDescription)
        }
    }

    /// Ends the follow; foca exits 0 on SIGTERM (design §8.5).
    func stop() {
        guard let p = process else { return }
        process = nil
        if p.isRunning {
            p.terminate()
        }
    }
}
