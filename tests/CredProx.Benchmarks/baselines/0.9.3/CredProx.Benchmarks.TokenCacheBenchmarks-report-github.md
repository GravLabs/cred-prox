```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method       | Mean            | Error        | StdDev       | Ratio     | RatioSD | Allocated | Alloc Ratio |
|------------- |----------------:|-------------:|-------------:|----------:|--------:|----------:|------------:|
| CacheHit     |        51.94 ns |     0.411 ns |     0.343 ns |      1.00 |    0.01 |         - |          NA |
| SingleFlight | 1,140,137.27 ns | 9,717.278 ns | 9,089.548 ns | 21,953.31 |  220.02 |   23520 B |          NA |
