```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method | Mean      | Error     | StdDev    | Ratio | RatioSD | Gen0   | Allocated | Alloc Ratio |
|------- |----------:|----------:|----------:|------:|--------:|-------:|----------:|------------:|
| Lookup |  5.355 ns | 0.1727 ns | 0.1615 ns |  1.00 |    0.04 |      - |         - |          NA |
| Expand | 28.199 ns | 0.7557 ns | 0.7069 ns |  5.27 |    0.20 | 0.0076 |      80 B |          NA |
