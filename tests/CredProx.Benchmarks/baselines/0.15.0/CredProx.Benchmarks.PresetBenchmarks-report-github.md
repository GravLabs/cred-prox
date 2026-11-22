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
| NoPresets   | 10.54 μs | 0.238 μs | 0.223 μs |  1.00 |    0.03 | 0.9088 |      - |   9.54 KB |        1.00 |
| WithPresets | 38.31 μs | 2.760 μs | 2.582 μs |  3.64 |    0.25 | 2.4793 | 0.8264 |   31.8 KB |        3.33 |
