# Benchmark Configuration Guide

This document describes how to configure the benchmark test output for the Sanitongo project.

## Environment Variables

### VERBOSE_BENCHMARK
Controls the level of detail in benchmark JSON output.

- **Default**: `false` (compact mode)
- **Values**: `1`, `true`, `yes` (case-insensitive) to enable verbose mode
- **Effect**: 
  - **Verbose mode**: Keeps all raw timing data (larger files, 80-100x bigger)
  - **Compact mode**: Keeps only descriptive statistics (min, 5th percentile, mean, median, 95th percentile, max, stddev, rounds)

### CI / GITHUB_ACTIONS
Controls whether machine information is included in the benchmark JSON.

- **Effect**:
  - **CI environment** (`CI=true` or `GITHUB_ACTIONS=true`): Includes machine_info section
  - **Local environment**: Excludes machine_info to protect privacy

## Usage Examples

### Run benchmarks locally (compact, no machine info)
```bash
pytest tests/test_benchmarks.py --benchmark-only --benchmark-json=benchmark.json
```

### Run benchmarks with verbose data
```bash
VERBOSE_BENCHMARK=true pytest tests/test_benchmarks.py --benchmark-only --benchmark-json=benchmark.json
```

### Simulate CI environment (with machine info)
```bash
CI=true pytest tests/test_benchmarks.py --benchmark-only --benchmark-json=benchmark.json
```

### Run all benchmarks with UV
```bash
uv run pytest tests/ -k "benchmark" --benchmark-only --benchmark-json=benchmark.json
```

## File Size Comparison

Based on a single benchmark test:

| Mode | File Size | Description |
|------|-----------|-------------|
| Compact (default) | ~1.1 KB | Only descriptive statistics |
| Verbose | ~94 KB | All raw timing data included |
| **Reduction** | **82x smaller** | Significant space saving for CI |

## Benchmark Statistics Included (Compact Mode)

- `min`: Minimum execution time
- `percentile_5`: 5th percentile (faster than 95% of runs)
- `mean`: Average execution time
- `median`: Median execution time (50th percentile)
- `percentile_95`: 95th percentile (slower than 95% of runs)
- `max`: Maximum execution time
- `stddev`: Standard deviation of timing measurements
- `rounds`: Number of benchmark rounds executed

## Integration with CI/CD

The GitHub Actions workflow automatically:

1. Uses `CI=true` to include machine info for debugging
2. Uses compact mode by default to minimize artifact size
3. Can be overridden with `VERBOSE_BENCHMARK=true` if detailed analysis is needed

## Privacy Considerations

Machine info includes:
- Node name (hostname)
- Processor architecture
- Python version and compiler details

This information is excluded when running locally to protect developer privacy, but included in CI for reproducibility and debugging.