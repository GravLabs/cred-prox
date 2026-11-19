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
| NoPresets   | 10.21 μs | 0.399 μs | 0.374 μs |  1.00 |    0.05 | 0.9052 |      - |   9.54 KB |        1.00 |
| WithPresets | 38.67 μs | 0.877 μs | 0.820 μs |  3.79 |    0.15 | 3.0093 | 0.6019 |   31.8 KB |        3.33 |
