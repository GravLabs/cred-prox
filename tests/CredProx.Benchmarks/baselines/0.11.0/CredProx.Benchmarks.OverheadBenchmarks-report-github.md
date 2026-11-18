```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method             | Mean      | Error     | StdDev    | Ratio | RatioSD | Gen0   | Gen1   | Allocated | Alloc Ratio |
|------------------- |----------:|----------:|----------:|------:|--------:|-------:|-------:|----------:|------------:|
| PlainYarp          |  71.89 μs |  3.392 μs |  3.173 μs |  1.00 |    0.06 | 0.5459 |      - |   5.55 KB |        1.00 |
| StaticKeyAttach    | 100.53 μs | 25.992 μs | 24.313 μs |  1.40 |    0.33 |      - |      - |   7.28 KB |        1.31 |
| OAuthCacheHit      |  79.17 μs |  5.546 μs |  4.917 μs |  1.10 |    0.08 | 0.6579 |      - |   7.68 KB |        1.38 |
| OAuthCacheHitScrub | 156.14 μs | 39.738 μs | 37.171 μs |  2.18 |    0.51 |      - |      - |   9.51 KB |        1.71 |
| SsePlain           | 139.05 μs | 25.575 μs | 23.923 μs |  1.94 |    0.33 | 0.8803 | 0.8803 |   8.82 KB |        1.59 |
| SseCredProx        | 236.53 μs | 35.262 μs | 32.984 μs |  3.30 |    0.47 |      - |      - |  11.48 KB |        2.07 |
