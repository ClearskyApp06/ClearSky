
# autocomplete

Caches are an optimization, but the slowest path (checking the DB) should be reasonably fast too.

## Cold cache: From the DB

```sql
SELECT handle FROM users
  WHERE users
  LIKE 'abc%';
```

This is probably very slow.

## Users prefix table?

```sql
CREATE TABLE IF NOT EXISTS user_prefixes (
  handle TEXT PRIMARY KEY,
  prefix1 TEXT NOT NULL,
  prefix2 TEXT NOT NULL,
  prefix3 TEXT NOT NULL,
);
CREATE INDEX idx_user_prefixes_prefix1 ON user_prefixes(prefix1);
CREATE INDEX idx_user_prefixes_prefix2 ON user_prefixes(prefix2);
CREATE INDEX idx_user_prefixes_prefix3 ON user_prefixes(prefix3);
```

## Inserting prefixes

```sql
INSERT INTO user_prefixes(handle, prefix1, prefix2, prefix3)
  VALUES(%s,
    SUBSTRING(handle, 1, 1),
    SUBSTRING(handle, 1, 2),
    SUBSTRING(handle, 1, 3)
  );
```

## Querying: Simple Case

Someone types in `ab`:

Closest prefix lookup is "ab":

```sql
SELECT handle FROM user_prefixes
  WHERE prefix3 = 'ab';
```

## Querying: Longer Case

Someone types in `abcdef`:

Maximum prefix size is 3, and lookup is "abc":

```sql
SELECT handle FROM user_prefixes
  WHERE prefix3 = 'abc'
  AND handle LIKE 'abcdef%';
```

You'd want to run this through `EXPLAIN` to see if postgres is smart enough to hit the prefix3 index before before scanning everything.

## Consideration: Querying Delay

Think about not firing off on each keyPress but after some sort of delay so if someone types "abc" real fast, it's one query for `abc` and not three for `a`, `ab`, `abc`.

## Consideration: Autocomplete limit

If you don't want to list all the handles that return for `a` then you can limit it in the query:


```sql
SELECT handle FROM user_prefixes
  WHERE prefix1 = 'a'
  LIMIT 10
```

## Using the Cache

You can use redis or memcache but it just needs to be:

```
key = prefix
value = flattened list of completions
time to live = ?
```

Check the cache first for the key, and if it's a miss, go to the database, get the results, and cache.
