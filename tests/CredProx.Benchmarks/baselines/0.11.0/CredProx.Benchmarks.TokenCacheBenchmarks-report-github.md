```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method       | Mean            | Error         | StdDev        | Ratio     | RatioSD | Allocated | Alloc Ratio |
|------------- |----------------:|--------------:|--------------:|----------:|--------:|----------:|------------:|
| CacheHit     |        49.98 ns |      1.381 ns |      1.291 ns |      1.00 |    0.04 |         - |          NA |
| SingleFlight | 1,151,663.23 ns | 15,765.830 ns | 14,747.368 ns | 23,058.30 |  637.32 |   23457 B |          NA |
