<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT 1 AS x, 2 AS x, 3 AS y"));
