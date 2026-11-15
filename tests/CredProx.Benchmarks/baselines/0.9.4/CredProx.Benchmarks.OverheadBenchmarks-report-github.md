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
| PlainYarp          | 118.47 μs | 35.252 μs | 32.974 μs |  1.07 |    0.41 |      - |   5.55 KB |        1.00 |
| StaticKeyAttach    |  91.74 μs | 21.277 μs | 19.903 μs |  0.83 |    0.28 |      - |   7.28 KB |        1.31 |
| OAuthCacheHit      |  81.24 μs |  2.924 μs |  2.735 μs |  0.74 |    0.19 | 0.4960 |   7.68 KB |        1.38 |
| OAuthCacheHitScrub | 107.68 μs | 26.836 μs | 25.103 μs |  0.97 |    0.34 |      - |    9.5 KB |        1.71 |
| SsePlain           | 136.53 μs | 26.409 μs | 24.703 μs |  1.24 |    0.39 |      - |   8.13 KB |        1.47 |
| SseCredProx        | 174.44 μs | 22.247 μs | 20.810 μs |  1.58 |    0.45 | 1.1792 |  12.81 KB |        2.31 |
