import UIKit

/// Covers the app's window the moment the app stops being active, which is
/// before iOS captures the image shown in the app switcher. SwiftUI's
/// `scenePhase` updates a frame too late for that capture, so the cover is
/// driven by UIKit notifications instead.
@MainActor
final class PrivacyScreen {
    static let shared = PrivacyScreen()

    private var started = false
    private weak var cover: UIView?

    private init() {}

    /// Idempotent: the app calls this on every launch of its root view.
    func start() {
        guard !started else { return }
        started = true

        let center = NotificationCenter.default
        center.addObserver(
            self,
            selector: #selector(coverWindows),
            name: UIApplication.willResignActiveNotification,
            object: nil
        )
        center.addObserver(
            self,
            selector: #selector(removeCover),
            name: UIApplication.didBecomeActiveNotification,
            object: nil
        )
    }

    @objc private func coverWindows() {
        guard cover == nil, let window = keyWindow else { return }
        let view = makeCover(for: window)
        window.addSubview(view)
        cover = view
    }

    @objc private func removeCover() {
        cover?.removeFromSuperview()
        cover = nil
    }

    private var keyWindow: UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow }
    }

    private func makeCover(for window: UIWindow) -> UIView {
        let view = UIView(frame: window.bounds)
        view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.backgroundColor = .systemBackground
        view.accessibilityIdentifier = "privacy-cover"

        let icon = UIImageView(image: UIImage(systemName: "lock.shield"))
        icon.tintColor = .secondaryLabel
        icon.preferredSymbolConfiguration = UIImage.SymbolConfiguration(pointSize: 44)

        let label = UILabel()
        label.text = "ScopeScan"
        label.font = .preferredFont(forTextStyle: .headline)
        label.textColor = .secondaryLabel

        let stack = UIStackView(arrangedSubviews: [icon, label])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])

        return view
    }
}
