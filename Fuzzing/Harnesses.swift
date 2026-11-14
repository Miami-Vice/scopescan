// Property checks shared by the libFuzzer targets.
//
// Compiled together with ScopeScanCore into each fuzz binary, so it
// deliberately does not import the module. A failed property traps, which
// libFuzzer records exactly like a crash.
//
// Nothing here touches the network, filesystem or Apple frameworks: these are
// the parsers that will consume bytes from untrusted LAN devices in M2/M3.

func fuzzIPv4Address(_ bytes: UnsafeRawBufferPointer) {
    let text = String(decoding: bytes, as: UTF8.self)
    guard let address = IPv4Address(text) else { return }

    // Anything the parser accepts must survive a description round trip.
    guard let reparsed = IPv4Address(address.description) else {
        preconditionFailure("description was not parseable: \(address.description)")
    }
    precondition(reparsed == address, "round trip changed \(address) into \(reparsed)")
}

func fuzzIPv4Network(_ bytes: UnsafeRawBufferPointer) {
    let text = String(decoding: bytes, as: UTF8.self)
    guard let network = IPv4Network(cidr: text) else { return }

    precondition((0...32).contains(network.prefixLength), "prefix out of range")
    precondition(network.contains(network.address), "network does not contain its own address")
    precondition(network.contains(network.broadcastAddress), "network does not contain its broadcast")

    // Round trip through the canonical form: the stored address may be a host
    // address, so compare the masked network address rather than the struct.
    guard let reparsed = IPv4Network(cidr: network.description) else {
        preconditionFailure("description was not parseable: \(network.description)")
    }
    precondition(reparsed.prefixLength == network.prefixLength, "prefix changed on round trip")
    precondition(reparsed.networkAddress == network.networkAddress, "network changed on round trip")
}

func fuzzScanScope(_ bytes: UnsafeRawBufferPointer) {
    let text = String(decoding: bytes, as: UTF8.self)

    do {
        let scope = try ScanScope(cidr: text)

        // The authorization guarantees, asserted rather than assumed.
        precondition(scope.network.prefixLength >= ScanScope.minimumPrefixLength, "scope larger than /22 was accepted")
        precondition(scope.hostCount <= ScanScope.maximumHostCount, "scope exceeds its host cap")
        precondition(scope.hostCount == scope.network.hostCount, "host count disagrees with the network")
        precondition(scope.hosts.count == scope.hostCount, "host list disagrees with its count")
        precondition(scope.cidr == scope.network.description, "cidr disagrees with the network")

        for host in scope.hosts.prefix(8) {
            precondition(scope.network.contains(host), "\(host) escaped \(scope.cidr)")
        }
        // A duplicate would make the sweep visit and report a target twice.
        precondition(Set(scope.hosts).count == scope.hostCount, "duplicate hosts in \(scope.cidr)")
    } catch {
        // Rejection is the expected outcome for almost every input.
    }
}

func fuzzOSVersion(_ bytes: UnsafeRawBufferPointer) {
    let text = String(decoding: bytes, as: UTF8.self)
    guard let version = OSVersion(string: text) else { return }

    guard let reparsed = OSVersion(string: version.description) else {
        preconditionFailure("description was not parseable: \(version.description)")
    }
    precondition(reparsed == version, "round trip changed \(version) into \(reparsed)")
    precondition(version.majorReleasesBehind(version) == 0, "version is behind itself")
}

func fuzzSSHBanner(_ bytes: UnsafeRawBufferPointer) {
    let input = Array(bytes)
    guard let banner = SSHBannerParser.parse(input) else { return }

    precondition(!banner.protocolVersion.isEmpty, "accepted an empty protocol version")
    precondition(!banner.software.isEmpty, "accepted an empty software version")
    // A banner is one line: nothing a server sends may smuggle a line break into the summary.
    precondition(!banner.summary.contains("\n") && !banner.summary.contains("\r"), "summary spans lines")
    precondition(banner.software.utf8.count + banner.protocolVersion.utf8.count <= SSHBannerParser.maximumLength,
                 "banner exceeds the RFC 4253 length limit")
}

func fuzzX509Validity(_ bytes: UnsafeRawBufferPointer) {
    let input = Array(bytes)
    let first = X509Validity.notAfter(certificateDER: input)
    // The parser is pure: the same bytes must always yield the same date.
    precondition(first == X509Validity.notAfter(certificateDER: input), "validity parse is not deterministic")
    if let date = first {
        precondition(date.timeIntervalSince1970.isFinite, "validity produced a non-finite date")
    }
}

func fuzzHTTPResponseHead(_ bytes: UnsafeRawBufferPointer) {
    let input = Array(bytes)
    guard let head = HTTPResponseParser.parse(input) else { return }

    precondition((100...599).contains(head.statusCode), "status \(head.statusCode) out of range")
    precondition(!head.reason.contains("\n") && !head.reason.contains("\r"), "reason spans lines")
    if let server = head.server {
        precondition(server.count <= HTTPResponseParser.maximumValueLength, "server value not truncated")
        precondition(server.allSatisfy(\.isASCII), "server value is not ASCII")
    }
}
