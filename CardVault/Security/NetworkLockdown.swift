import Foundation

/// Defense-in-depth process-level network kill-switch.
/// CardSe contains zero networking code, and additionally registers `OfflineKillSwitchURLProtocol`
/// plus zero-capacity URL caches/cookies so any inadvertent Foundation URL loading immediately fails offline.
@objc(CardSeOfflineKillSwitchURLProtocol)
final class OfflineKillSwitchURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else { return true }
        return !url.isFileURL
    }

    override class func canInit(with task: URLSessionTask) -> Bool {
        guard let url = task.currentRequest?.url ?? task.originalRequest?.url else { return true }
        return !url.isFileURL
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
    }

    override func stopLoading() {}
}

enum NetworkLockdown {
    private static var isActivated = false

    static func activate() {
        guard !isActivated else { return }
        isActivated = true

        URLProtocol.registerClass(OfflineKillSwitchURLProtocol.self)
        URLCache.shared = URLCache(memoryCapacity: 0, diskCapacity: 0, directory: nil)
        HTTPCookieStorage.shared.cookieAcceptPolicy = .never
    }
}
