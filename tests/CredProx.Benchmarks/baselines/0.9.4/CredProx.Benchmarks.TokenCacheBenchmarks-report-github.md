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
| CacheHit     |        52.48 ns |      1.452 ns |      1.358 ns |      1.00 |    0.04 |         - |          NA |
| SingleFlight | 1,148,421.62 ns | 16,434.937 ns | 13,723.916 ns | 21,897.38 |  607.18 |   23449 B |          NA |
