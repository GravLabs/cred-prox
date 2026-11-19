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
| PlainYarp          |  68.29 μs |  2.203 μs |  2.061 μs |  1.00 |    0.04 | 0.2815 |   5.55 KB |        1.00 |
| StaticKeyAttach    | 144.15 μs | 40.995 μs | 38.346 μs |  2.11 |    0.55 |      - |    7.4 KB |        1.33 |
| OAuthCacheHit      |  76.28 μs |  2.050 μs |  1.711 μs |  1.12 |    0.04 | 0.5000 |   7.79 KB |        1.40 |
| OAuthCacheHitScrub |  83.01 μs |  1.695 μs |  1.503 μs |  1.22 |    0.04 | 0.6410 |   9.61 KB |        1.73 |
| SsePlain           | 151.51 μs | 38.468 μs | 35.983 μs |  2.22 |    0.51 | 0.9615 |    9.7 KB |        1.75 |
| SseCredProx        | 133.57 μs | 16.533 μs | 15.465 μs |  1.96 |    0.23 | 0.7911 |  11.93 KB |        2.15 |
