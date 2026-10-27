<?php $db = sqlite_open(":memory:"); var_dump(sqlite_query($db, "SELECT ? AS s, length(?) AS chars, upper(?) AS up", ["héllo wörld 日本", "日本", "abc"]));
