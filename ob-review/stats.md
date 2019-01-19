# Some data I collected

I did that for my own education to get a feel for the code base, but it might
also be interesting for you, so I added it.

## code to test ratio

raiden has 333 unit tests and 136 integration tests

## Source lines of code

All code:

```
SLOC    Directory       SLOC-by-Language (Sorted)
43182   raiden          python=43182
3561    tools           python=3454,sh=107
96      top_dir         python=60,sh=36
78      docs            python=78

Totals grouped by language (dominant language first):
python:       46774 (99.70%)
sh:             143 (0.30%)

Total Physical Source Lines of Code (SLOC)                = 46,917
Development Effort Estimate, Person-Years (Person-Months) = 11.37 (136.49)
 (Basic COCOMO model, Person-Months = 2.4 * (KSLOC**1.05))
Schedule Estimate, Years (Months)                         = 1.35 (16.19)
 (Basic COCOMO model, Months = 2.5 * (person-months**0.38))
Estimated Average Number of Developers (Effort/Schedule)  = 8.43
Total Estimated Cost to Develop                           = $ 1,536,521
 (average salary = $56,286/year, overhead = 2.40).
SLOCCount, Copyright (C) 2001-2004 David A. Wheeler
```

raiden/tests only:

```
SLOC    Directory       SLOC-by-Language (Sorted)
7862    integration     python=7862
7756    unit            python=7756
2487    utils           python=2487
162     fixtures        python=162
138     top_dir         python=138
29      benchmark       python=29

Total Physical Source Lines of Code (SLOC)                = 18,434
```

* Installation of the Python specific dependencies takes about 2:30 min on a decent developer Laptop
