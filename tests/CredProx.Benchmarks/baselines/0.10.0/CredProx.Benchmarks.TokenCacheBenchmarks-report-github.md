```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method       | Mean            | Error         | StdDev        | Ratio     | RatioSD  | Allocated | Alloc Ratio |
|------------- |----------------:|--------------:|--------------:|----------:|---------:|----------:|------------:|
| CacheHit     |        52.54 ns |      1.245 ns |      1.165 ns |      1.00 |     0.03 |         - |          NA |
| SingleFlight | 1,206,555.57 ns | 65,646.926 ns | 61,406.175 ns | 22,973.94 | 1,236.14 |   23434 B |          NA |
