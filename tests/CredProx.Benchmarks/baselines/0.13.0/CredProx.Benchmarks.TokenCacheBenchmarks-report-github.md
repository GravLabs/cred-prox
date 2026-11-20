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
| CacheHit     |        51.55 ns |      1.802 ns |      1.686 ns |      1.00 |    0.04 |         - |          NA |
| SingleFlight | 1,154,575.79 ns | 16,170.477 ns | 14,334.706 ns | 22,418.17 |  746.75 |   23448 B |          NA |
