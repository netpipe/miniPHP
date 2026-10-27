<?php $db = sqlite_open(":memory:"); var_dump(sqlite_close($db)); var_dump(sqlite_query($db, "SELECT 1")); var_dump(sqlite_close($db)); var_dump(sqlite_query(99, "SELECT 1"));
