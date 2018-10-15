query:
 	select ;

select:
	SELECT GROUPBY_FIELDS FROM BUCKET_NAME WHERE complex_condition GROUP BY NUMERIC_FIELD_LIST HAVING numeric_condition |
	SELECT GROUPBY_FIELDS FROM BUCKET_NAME WHERE complex_condition GROUP BY STRING_FIELD_LIST HAVING string_condition  |
	SELECT GROUPBY_FIELDS FROM BUCKET_NAME WHERE complex_condition GROUP BY NUMERIC_FIELD_LIST,STRING_FIELD_LIST HAVING (string_condition) AND  (numeric_condition);
	SELECT numeric_aggregate_method  FROM BUCKET_NAME WHERE complex_condition GROUP BY NUMERIC_FIELD_LIST HAVING numeric_condition |
	SELECT generic_aggregate_method  FROM BUCKET_NAME WHERE complex_condition GROUP BY NUMERIC_FIELD_LIST HAVING numeric_condition ;
	SELECT numeric_aggregate_method  FROM BUCKET_NAME WHERE complex_condition GROUP BY STRING_FIELD_LIST HAVING numeric_condition |
	SELECT generic_aggregate_method  FROM BUCKET_NAME WHERE complex_condition GROUP BY STRING_FIELD_LIST HAVING string_condition ;

numeric_aggregate_method:
	COUNT(*) AS AGGREGATE_FIELD | COUNT(FIELD) AS AGGREGATE_FIELD | aggregate_function(FIELD) AS AGGREGATE_FIELD | SUM(FIELD) AS AGGREGATE_FIELD | numeric_aggregate_method, numeric_aggregate_method ;

aggregate_function:
    AVG | STDDEV | VARIANCE | STDDEV_SAMP | STDDEV_POP | VARIANCE_POP | VARIANCE_SAMP | MEAN ;

generic_aggregate_method:
	MAX(FIELD) AS AGGREGATE_FIELD | MIN(FIELD) AS AGGREGATE_FIELD | generic_aggregate_method, generic_aggregate_method ;

direction:
	ASC | DESC;


complex_condition:
	NOT (condition) | (condition) AND (condition) | (condition) OR (condition) | (condition) AND (condition) OR (condition) AND (condition) | condition;

condition:
	numeric_condition | string_condition | bool_condition | (string_condition AND numeric_condition) |
	(numeric_condition OR string_condition) | (bool_condition AND numeric_condition) |  (bool_condition OR numeric_condition) |
	 (bool_condition AND numeric_condition) | (bool_condition OR string_condition) |
	 (bool_condition AND string_condition) | (numeric_condition AND string_condition AND bool_condition);

field:
	NUMERIC_FIELD | STRING_FIELD;

non_string_field:
	NUMERIC_FIELD;


# NUMERIC RULES

numeric_condition:
	numeric_field comparison_operators numeric_value |
	(numeric_condition) AND (numeric_condition)|
	(numeric_condition) OR (numeric_condition)|
	NOT (numeric_condition) |
	numeric_between_condition |
	numeric_is_not_null |
	numeric_is_null |
	numeric_in_conidtion ;

numeric_equals_condition:
	numeric_field = numeric_value ;

numeric_not_equals_condition:
	numeric_field != numeric_value ;

numeric_in_conidtion:
	numeric_field IN ( numeric_field_list );

numeric_between_condition:
	NUMERIC_FIELD BETWEEN LOWER_BOUND_VALUE and UPPER_BOUND_VALUE;

numeric_not_between_condition:
	NUMERIC_FIELD NOT BETWEEN LOWER_BOUND_VALUE and UPPER_BOUND_VALUE;

numeric_is_not_null:
	NUMERIC_FIELD IS NOT NULL;

numeric_is_missing:
	NUMERIC_FIELD IS MISSING;

numeric_is_not_missing:
	NUMERIC_FIELD IS NOT MISSING;

numeric_is_valued:
	NUMERIC_FIELD IS VALUED;

numeric_is_not_valued:
	NUMERIC_FIELD IS NOT VALUED;

numeric_is_null:
	NUMERIC_FIELD IS NULL;

numeric_field_list:
	LIST;

numeric_field:
	NUMERIC_FIELD;

numeric_value:
	NUMERIC_VALUE;

# STRING RULES

string_condition:
	string_field comparison_operators string_values |
	(string_condition) AND (string_condition) |
	(string_condition) OR (string_condition) |
	string_not_between_condition |
	NOT (string_condition) |
	string_is_not_null |
	string_is_null |
	string_in_conidtion |
	string_equals_condition ;

string_equals_condition:
	string_field = string_values;

string_not_equals_condition:
	string_field != string_values | string_field <> string_values ;

string_between_condition:
	string_field BETWEEN LOWER_BOUND_VALUE and UPPER_BOUND_VALUE;

string_not_between_condition:
	string_field NOT BETWEEN LOWER_BOUND_VALUE and UPPER_BOUND_VALUE;

string_is_not_null:
	string_field IS NOT NULL;

string_in_conidtion:
	string_field IN ( string_field_list );

string_is_null:
	string_field IS NULL;

string_field_list:
	LIST;

string_is_missing:
	STRING_FIELD IS MISSING;

string_is_not_missing:
	STRING_FIELD IS NOT MISSING;

string_is_valued:
	STRING_FIELD IS VALUED;

string_is_not_valued:
	STRING_FIELD IS NOT VALUED;

string_field:
	STRING_FIELD;

string_values:
	STRING_VALUES;

# BOOLEAN RULES

bool_condition:
	NOT (bool_field) |
	bool_equals_condition |
	bool_not_equals_condition ;

bool_equals_condition:
	bool_field = bool_value;

bool_not_equals_condition:
	bool_field != bool_value ;

bool_field:
	BOOL_FIELD;

bool_value:
	true | false;

field_list:
	NUMERIC_FIELD_LIST | STRING_FIELD_LIST | NUMERIC_FIELD_LIST, STRING_FIELD_LIST | NUMERIC_FIELD_LIST, STRING_FIELD_LIST, BOOL_FIELD_LIST;

comparison_operators:
	<> | != | = | > | < | >= | <= ;
