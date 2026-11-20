```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method             | Mean      | Error     | StdDev    | Ratio | RatioSD | Gen0   | Allocated | Alloc Ratio |
|------------------- |----------:|----------:|----------:|------:|--------:|-------:|----------:|------------:|
| PlainYarp          |  71.37 μs |  7.290 μs |  6.087 μs |  1.01 |    0.11 |      - |   5.55 KB |        1.00 |
| StaticKeyAttach    |  77.36 μs |  1.451 μs |  1.211 μs |  1.09 |    0.08 | 0.5952 |   7.28 KB |        1.31 |
| OAuthCacheHit      |  82.14 μs |  3.725 μs |  3.485 μs |  1.16 |    0.10 | 0.4808 |   7.68 KB |        1.38 |
| OAuthCacheHitScrub | 106.47 μs | 23.392 μs | 21.881 μs |  1.50 |    0.32 | 0.9058 |    9.5 KB |        1.71 |
| SsePlain           | 125.54 μs | 21.190 μs | 19.822 μs |  1.77 |    0.30 |      - |    7.1 KB |        1.28 |
| SseCredProx        | 240.98 μs | 36.913 μs | 34.529 μs |  3.40 |    0.53 |      - |  11.78 KB |        2.12 |
