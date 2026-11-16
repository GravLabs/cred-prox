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
| PlainYarp          |  91.54 μs | 18.023 μs | 15.050 μs |  1.02 |    0.23 |      - |   5.55 KB |        1.00 |
| StaticKeyAttach    |  76.44 μs |  1.414 μs |  1.181 μs |  0.86 |    0.13 | 0.6410 |   7.28 KB |        1.31 |
| OAuthCacheHit      |  74.74 μs |  1.387 μs |  1.158 μs |  0.84 |    0.13 | 0.4630 |   7.68 KB |        1.38 |
| OAuthCacheHitScrub |  83.41 μs |  3.102 μs |  2.901 μs |  0.93 |    0.15 | 0.6944 |    9.5 KB |        1.71 |
| SsePlain           | 136.26 μs | 22.589 μs | 21.130 μs |  1.53 |    0.33 | 0.9470 |   9.73 KB |        1.75 |
| SseCredProx        | 194.06 μs | 29.929 μs | 27.996 μs |  2.17 |    0.46 | 1.2255 |   13.3 KB |        2.40 |
