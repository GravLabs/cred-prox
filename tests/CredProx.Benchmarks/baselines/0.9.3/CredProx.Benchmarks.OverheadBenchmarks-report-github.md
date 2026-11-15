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
| PlainYarp          |  68.89 μs |  1.812 μs |  1.513 μs |  1.00 |    0.03 | 0.2880 |   5.55 KB |        1.00 |
| StaticKeyAttach    |  89.12 μs | 20.323 μs | 18.015 μs |  1.29 |    0.25 |      - |   7.29 KB |        1.31 |
| OAuthCacheHit      |  88.43 μs | 13.431 μs | 11.216 μs |  1.28 |    0.16 | 0.7530 |   7.68 KB |        1.38 |
| OAuthCacheHitScrub |  83.17 μs |  2.440 μs |  2.163 μs |  1.21 |    0.04 | 0.7353 |    9.5 KB |        1.71 |
| SsePlain           | 149.58 μs | 30.054 μs | 28.113 μs |  2.17 |    0.40 |      - |   8.56 KB |        1.54 |
| SseCredProx        | 201.43 μs | 27.825 μs | 26.027 μs |  2.93 |    0.37 | 1.2255 |  14.13 KB |        2.55 |
