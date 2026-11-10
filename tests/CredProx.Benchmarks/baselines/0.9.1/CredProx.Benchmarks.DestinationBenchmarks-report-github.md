```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.114
  [Host]     : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method | Mean      | Error     | StdDev    | Ratio | RatioSD | Gen0   | Allocated | Alloc Ratio |
|------- |----------:|----------:|----------:|------:|--------:|-------:|----------:|------------:|
| Lookup |  6.239 ns | 0.0426 ns | 0.0398 ns |  1.00 |    0.01 |      - |         - |          NA |
| Expand | 29.759 ns | 0.3859 ns | 0.3421 ns |  4.77 |    0.06 | 0.0076 |      80 B |          NA |
