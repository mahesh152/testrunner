query:
    select;

select:
    SELECT select_from FROM BUCKET_NAME WHERE where_condition ORDER BY VAL |
    SELECT primary_key_id, COALESCE(field,field,field,field) as VAL FROM BUCKET_NAME WHERE where_condition ORDER BY primary_key_id |
    SELECT DISTINCT(COALESCE(numeric_field, numeric_field)) as VAL FROM BUCKET_NAME WHERE 1=1 ORDER BY VAL |
    SELECT select_from1 FROM BUCKET_NAME WHERE 1=1 GROUP BY numeric_field1 HAVING having_condition |
    SELECT primary_key_id, NVL(field, field) as VAL FROM BUCKET_NAME WHERE where_condition ORDER BY primary_key_id |
    SELECT DISTINCT(NVL(numeric_field, numeric_field)) as VAL FROM BUCKET_NAME WHERE 1=1 ORDER BY VAL;


field:
    NUMERIC_FIELD | STRING_FIELD | BOOL_FIELD | DATETIME_FIELD;

select_from:
    select_from_coalesce | select_from_nvl ;

select_from_coalesce:
    aggregate_func(COALESCE(numeric_field,numeric_field)) as VAL ;

select_from_nvl:
    aggregate_func(NVL(numeric_field,numeric_field)) as VAL;

select_from1:
    numeric_field1 ;

numeric_field:
    NUMERIC_FIELD | NUMERIC_FIELD ;

numeric_field1:
    NUMERIC_FIELD ;

aggregate_func:
    COUNT | MIN | MAX | aggregate_function | SUM ;

aggregate_function:
    AVG | STDDEV | VARIANCE | STDDEV_SAMP | STDDEV_POP | VARIANCE_POP | VARIANCE_SAMP | MEAN ;

where_condition:
    1=1 | COALESCE(numeric_field, 10) > 0 |
    NVL(numeric_field, 10) > 0 ;

having_condition:
    aggregate_func(COALESCE(numeric_field1, 10)) > 0 |
    aggregate_func(NVL(numeric_field1, 10)) > 0 ;
