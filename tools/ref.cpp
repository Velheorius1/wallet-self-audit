// Reference generator for std::mt19937 + std::seed_seq fixtures.
// Compile:  clang++ -std=c++17 -O2 tools/ref.cpp -o tools/ref
// Run:      tools/ref > tests/fixtures/prng/mt19937_cpp_ref.json
//
// Goal: produce exactly the same outputs that bx (libbitcoin-explorer)
// produced via std::mt19937(std::seed_seq{<timestamp>}). The first 4
// uint32 outputs, big-endian-packed, are the 128-bit BIP-39 entropy
// of a Milk Sad-vulnerable wallet.
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

void emit(const std::vector<uint32_t>& v, int n_outputs) {
    std::seed_seq ss(v.begin(), v.end());
    std::mt19937 g(ss);
    std::printf("    {\n      \"seed_seq_input\": [");
    for (size_t i = 0; i < v.size(); ++i) {
        std::printf("%s%u", (i == 0 ? "" : ", "), v[i]);
    }
    std::printf("],\n      \"first_outputs\": [");
    for (int i = 0; i < n_outputs; ++i) {
        std::printf("%s%u", (i == 0 ? "" : ", "), g());
    }
    std::printf("]\n    }");
}

int main() {
    std::printf("{\n  \"_comment\": \"std::mt19937 + std::seed_seq reference outputs (C++ libc++/libstdc++ portable).\",\n  \"cases\": [\n");

    // Single-input seed_seq cases — these match the bx seed flow.
    // 0 (a corner case the libc++ test suite hits)
    emit({0u}, 8); std::printf(",\n");
    // 1, 2, small numbers for distinguishing the algorithm
    emit({1u}, 8); std::printf(",\n");
    emit({2u}, 8); std::printf(",\n");
    // Some realistic Milk Sad-era timestamps (unix seconds).
    emit({1577836800u}, 8); std::printf(",\n"); // 2020-01-01 00:00:00 UTC
    emit({1609459200u}, 8); std::printf(",\n"); // 2021-01-01 00:00:00 UTC
    emit({1640995200u}, 8); std::printf(",\n"); // 2022-01-01 00:00:00 UTC
    emit({1672531200u}, 8); std::printf(",\n"); // 2023-01-01 00:00:00 UTC
    emit({1692057600u}, 8); std::printf(",\n"); // 2023-08-15 00:00:00 UTC (CVE patch date)
    // Multi-input cases.
    emit({1u, 2u, 3u}, 8); std::printf(",\n");
    emit({0xCAFEBABEu, 0xDEADBEEFu}, 8); std::printf("\n");

    std::printf("  ]\n}\n");
    return 0;
}
