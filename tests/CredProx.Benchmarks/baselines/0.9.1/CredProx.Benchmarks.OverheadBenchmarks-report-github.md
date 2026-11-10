```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.114
  [Host]     : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method             | Mean      | Error     | StdDev    | Ratio | RatioSD | Gen0    | Gen1    | Allocated | Alloc Ratio |
|------------------- |----------:|----------:|----------:|------:|--------:|--------:|--------:|----------:|------------:|
| PlainYarp          | 106.54 μs | 43.681 μs | 40.859 μs |  1.13 |    0.57 |       - |       - |   5.55 KB |        1.00 |
| StaticKeyAttach    |  80.58 μs |  3.746 μs |  3.504 μs |  0.85 |    0.27 |  0.6477 |       - |   7.28 KB |        1.31 |
| OAuthCacheHit      | 133.12 μs | 47.733 μs | 44.650 μs |  1.41 |    0.66 |       - |       - |   7.68 KB |        1.38 |
| OAuthCacheHitScrub |  86.39 μs |  1.273 μs |  1.190 μs |  0.92 |    0.29 |  4.1209 |  0.3434 |  41.65 KB |        7.51 |
| SsePlain           | 467.45 μs | 48.381 μs | 45.256 μs |  4.95 |    1.65 |  6.0484 |  4.0323 |  62.62 KB |       11.29 |
| SseCredProx        | 620.55 μs | 40.438 μs | 35.847 μs |  6.57 |    2.13 | 10.8696 | 10.8696 | 113.52 KB |       20.46 |
