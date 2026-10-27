<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT json_object('a', ?, 'b', ?) AS j, json_extract('{\"x\":[1,2]}', '$.x[1]') AS e", [1, "two"]));
