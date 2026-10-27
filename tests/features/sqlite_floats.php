<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT ? AS a, 0.1 + 0.2 AS b, 1e300 * 10 AS c, 7 / 2 AS d, 7.0 / 2 AS e", [1.5]));
