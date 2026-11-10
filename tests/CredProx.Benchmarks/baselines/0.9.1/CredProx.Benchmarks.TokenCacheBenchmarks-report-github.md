```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.114
  [Host]     : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method       | Mean            | Error         | StdDev        | Ratio     | RatioSD | Allocated | Alloc Ratio |
|------------- |----------------:|--------------:|--------------:|----------:|--------:|----------:|------------:|
| CacheHit     |        54.43 ns |      0.338 ns |      0.317 ns |      1.00 |    0.01 |         - |          NA |
| SingleFlight | 1,147,609.65 ns | 14,147.723 ns | 13,233.789 ns | 21,083.95 |  263.79 |   23520 B |          NA |
