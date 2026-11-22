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
| PlainYarp          |  76.00 μs |  9.442 μs |  8.832 μs |  1.01 |    0.16 |      - |   5.55 KB |        1.00 |
| StaticKeyAttach    | 129.53 μs | 38.271 μs | 35.798 μs |  1.72 |    0.50 |      - |   7.28 KB |        1.31 |
| OAuthCacheHit      | 125.74 μs | 30.978 μs | 28.976 μs |  1.67 |    0.42 |      - |   7.68 KB |        1.38 |
| OAuthCacheHitScrub |  85.68 μs |  4.994 μs |  4.671 μs |  1.14 |    0.13 | 0.5297 |   9.53 KB |        1.72 |
| SsePlain           | 138.22 μs | 34.173 μs | 31.965 μs |  1.84 |    0.46 |      - |   7.06 KB |        1.27 |
| SseCredProx        | 251.84 μs | 43.981 μs | 41.140 μs |  3.35 |    0.64 |      - |   11.7 KB |        2.11 |
