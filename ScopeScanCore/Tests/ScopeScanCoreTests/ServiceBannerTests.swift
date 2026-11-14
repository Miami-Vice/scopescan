import XCTest
@testable import ScopeScanCore

final class ServiceBannerTests: XCTestCase {
    private func bytes(_ text: String) -> [UInt8] {
        Array(text.utf8)
    }

    // MARK: - SSH

    func testParsesOpenSSHBanner() {
        let banner = SSHBannerParser.parse(bytes("SSH-2.0-OpenSSH_9.6\r\n"))
        XCTAssertEqual(banner?.protocolVersion, "2.0")
        XCTAssertEqual(banner?.software, "OpenSSH_9.6")
        XCTAssertEqual(banner?.summary, "SSH 2.0, OpenSSH_9.6")
    }

    func testAcceptsBareLineFeed() {
        XCTAssertEqual(SSHBannerParser.parse(bytes("SSH-1.99-dropbear_2020\n"))?.software, "dropbear_2020")
    }

    func testKeepsSoftwareWithComments() {
        let banner = SSHBannerParser.parse(bytes("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"))
        XCTAssertEqual(banner?.software, "OpenSSH_8.9p1 Ubuntu-3")
    }

    func testRejectsNonSSHData() {
        XCTAssertNil(SSHBannerParser.parse(bytes("HTTP/1.1 200 OK\r\n")))
        XCTAssertNil(SSHBannerParser.parse(bytes("SSH-2.0")))
        XCTAssertNil(SSHBannerParser.parse([]))
    }

    func testRejectsEmptyFields() {
        XCTAssertNil(SSHBannerParser.parse(bytes("SSH--\r\n")))
        XCTAssertNil(SSHBannerParser.parse(bytes("SSH-2.0-\r\n")))
    }

    func testRejectsControlBytesInBanner() {
        XCTAssertNil(SSHBannerParser.parse([0x53, 0x53, 0x48, 0x2D, 0x32, 0x00, 0x0A]))
    }

    func testRejectsBannerLongerThanRFCLimit() {
        let long = "SSH-2.0-" + String(repeating: "a", count: 300) + "\r\n"
        XCTAssertNil(SSHBannerParser.parse(bytes(long)))
    }

    // MARK: - HTTP

    func testParsesStatusAndServer() {
        let head = HTTPResponseParser.parse(bytes("HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Length: 0\r\n\r\n"))
        XCTAssertEqual(head?.statusCode, 200)
        XCTAssertEqual(head?.reason, "OK")
        XCTAssertEqual(head?.server, "nginx/1.25")
        XCTAssertEqual(head?.summary, "HTTP 200, Server: nginx/1.25")
    }

    func testServerHeaderIsCaseInsensitive() {
        let head = HTTPResponseParser.parse(bytes("HTTP/1.0 401 Unauthorized\r\nSERVER: lighttpd\r\n\r\n"))
        XCTAssertEqual(head?.statusCode, 401)
        XCTAssertEqual(head?.server, "lighttpd")
    }

    func testMissingServerHeaderIsNil() {
        let head = HTTPResponseParser.parse(bytes("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"))
        XCTAssertEqual(head?.statusCode, 302)
        XCTAssertNil(head?.server)
        XCTAssertEqual(head?.summary, "HTTP 302")
    }

    func testRejectsNonHTTP() {
        XCTAssertNil(HTTPResponseParser.parse(bytes("SSH-2.0-OpenSSH\r\n")))
        XCTAssertNil(HTTPResponseParser.parse(bytes("HTTP/2 200\r\n")))
        XCTAssertNil(HTTPResponseParser.parse(bytes("HTTP/1.1 999 Nope\r\n")))
        XCTAssertNil(HTTPResponseParser.parse(bytes("HTTP/1.1 abc\r\n")))
        XCTAssertNil(HTTPResponseParser.parse([]))
    }

    func testIgnoresOversizedServerValue() {
        let value = String(repeating: "x", count: 500)
        let head = HTTPResponseParser.parse(bytes("HTTP/1.1 200 OK\r\nServer: \(value)\r\n\r\n"))
        XCTAssertEqual(head?.server?.count, HTTPResponseParser.maximumValueLength)
    }

    func testIgnoresNonASCIIServerValue() {
        let head = HTTPResponseParser.parse(bytes("HTTP/1.1 200 OK\r\nServer: caf\u{00E9}\r\n\r\n"))
        XCTAssertNil(head?.server)
    }

    func testHeadWithoutTerminatorIsStillParsed() {
        let head = HTTPResponseParser.parse(bytes("HTTP/1.1 200 OK\r\nServer: partial"))
        XCTAssertEqual(head?.server, "partial")
    }
}
