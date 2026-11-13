import Foundation
import Observation
import ScopeScanCore

/// Holds the latest posture observation and the findings derived from it, so the
/// Scan and Posture tabs agree on one snapshot.
@Observable
final class PostureStore {
    private(set) var observation = PostureObservation()
    private(set) var findings: [Finding] = []
    private(set) var lastRefreshed: Date?
    private(set) var isRefreshing = false

    private let evaluator = PostureEvaluator()

    @MainActor
    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        let collected = PostureCollector.collect()
        observation = collected
        findings = evaluator.evaluate(collected)
        lastRefreshed = Date()
    }

    /// Collects once, then stays put. The Scan tab uses this so switching tabs
    /// does not re-run LocalAuthentication on every appearance.
    @MainActor
    func refreshIfNeeded() async {
        guard lastRefreshed == nil else { return }
        await refresh()
    }

    var highestSeverity: Severity? {
        findings.highestSeverity
    }

    /// The iOS version the evaluator judges against, for display alongside the
    /// installed version.
    var recommendedOS: OSVersion {
        evaluator.policy.recommendedOS
    }
}
