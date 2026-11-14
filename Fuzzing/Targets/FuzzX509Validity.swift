// libFuzzer entry point. The fuzzer runtime supplies `main`; this target is
// compiled with -parse-as-library so Swift does not generate one.

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    fuzzX509Validity(UnsafeRawBufferPointer(start: start, count: count))
    return 0
}
