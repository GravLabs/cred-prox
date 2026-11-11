```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.114
  [Host]     : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method             | Mean      | Error     | StdDev    | Ratio | RatioSD | Gen0   | Gen1   | Allocated | Alloc Ratio |
|------------------- |----------:|----------:|----------:|------:|--------:|-------:|-------:|----------:|------------:|
| PlainYarp          |  71.10 μs |  3.696 μs |  3.458 μs |  1.00 |    0.07 | 0.2778 |      - |   5.55 KB |        1.00 |
| StaticKeyAttach    |  81.18 μs |  3.576 μs |  3.345 μs |  1.14 |    0.07 | 0.6281 |      - |   7.28 KB |        1.31 |
| OAuthCacheHit      |  99.82 μs | 29.187 μs | 27.301 μs |  1.41 |    0.38 |      - |      - |   7.68 KB |        1.38 |
| OAuthCacheHitScrub |  88.31 μs |  4.326 μs |  4.046 μs |  1.24 |    0.08 | 0.6831 |      - |    9.5 KB |        1.71 |
| SsePlain           | 477.40 μs | 40.268 μs | 37.667 μs |  6.73 |    0.60 | 6.0484 | 6.0484 |   63.5 KB |       11.44 |
| SseCredProx        | 566.84 μs | 81.751 μs | 72.470 μs |  7.99 |    1.05 | 7.8125 | 5.2083 |  80.45 KB |       14.49 |
