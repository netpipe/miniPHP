<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT sqrt(16) AS r, pow(2, 10) AS p, abs(-3) AS a, round(2.567, 2) AS rd"));
