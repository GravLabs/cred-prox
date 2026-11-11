```

BenchmarkDotNet v0.15.8, Linux Ubuntu 26.04.1 LTS (Resolute Raccoon)
Intel Core i9-10900KF CPU 3.70GHz (Max: 0.80GHz), 1 CPU, 20 logical and 10 physical cores
.NET SDK 10.0.114
  [Host]     : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3
  Job-WDNCLO : .NET 10.0.14 (10.0.14, 10.0.1426.52326), X64 RyuJIT x86-64-v3

IterationCount=15  IterationTime=250ms  LaunchCount=1  
WarmupCount=5  

```
| Method      | Mean     | Error    | StdDev   | Ratio | RatioSD | Gen0   | Gen1   | Allocated | Alloc Ratio |
|------------ |---------:|---------:|---------:|------:|--------:|-------:|-------:|----------:|------------:|
| NoPresets   | 10.61 μs | 0.099 μs | 0.093 μs |  1.00 |    0.01 | 0.9316 |      - |   9.54 KB |        1.00 |
| WithPresets | 40.67 μs | 0.498 μs | 0.442 μs |  3.83 |    0.05 | 3.0419 | 0.6404 |   31.8 KB |        3.33 |
