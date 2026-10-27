<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELEC 1")); echo sqlite_error($db);
