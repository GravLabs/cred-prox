```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.115
  [Host]     : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.15 (10.0.15, 10.0.1526.53008), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method      | Mean     | Error    | StdDev   | Ratio | RatioSD | Gen0   | Gen1   | Allocated | Alloc Ratio |
|------------ |---------:|---------:|---------:|------:|--------:|-------:|-------:|----------:|------------:|
| NoPresets   | 10.28 μs | 0.331 μs | 0.310 μs |  1.00 |    0.04 | 0.9150 |      - |   9.54 KB |        1.00 |
| WithPresets | 39.23 μs | 0.908 μs | 0.805 μs |  3.82 |    0.13 | 3.0243 | 0.6049 |   31.8 KB |        3.33 |
