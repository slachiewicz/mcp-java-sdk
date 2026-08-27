/*
 * Copyright 2026-2026 the original author or authors.
 */
package io.modelcontextprotocol.json.schema;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.modelcontextprotocol.json.schema.jackson3.DefaultJsonSchemaValidator;

/**
 * SEP-2106 audit probe: exercises JSON Schema 2020-12-specific keywords through the
 * default validator to confirm end-to-end dialect coverage.
 */
class Sep2106KeywordProbeTests {

	private final DefaultJsonSchemaValidator validator = new DefaultJsonSchemaValidator();

	private Map<String, Object> s(Object... kv) {
		var map = new LinkedHashMap<String, Object>();
		for (int i = 0; i < kv.length; i += 2) {
			map.put((String) kv[i], kv[i + 1]);
		}
		return map;
	}

	@Test
	void prefixItemsAndItems() {
		var schema = s("type", "array", "prefixItems", List.of(s("type", "string"), s("type", "integer")), "items",
				s("type", "boolean"));
		assertThat(this.validator.validate(schema, List.of("a", 1, true)).valid()).isTrue();
		assertThat(this.validator.validate(schema, List.of("a", 1, "not-bool")).valid()).isFalse();
		assertThat(this.validator.validate(schema, List.of(1, "a")).valid()).isFalse();
	}

	@Test
	void unevaluatedProperties() {
		var schema = s("type", "object", "properties", s("known", s("type", "string")), "patternProperties",
				s("^opt_", s("type", "integer")), "unevaluatedProperties", false);
		assertThat(this.validator.validate(schema, s("known", "x")).valid()).isTrue();
		assertThat(this.validator.validate(schema, s("known", "x", "opt_n", 2)).valid()).isTrue();
		assertThat(this.validator.validate(schema, s("known", "x", "other", 1)).valid()).isFalse();
	}

	@Test
	void dependentRequired() {
		var schema = s("type", "object", "dependentRequired", s("credit_card", List.of("billing_address")));
		assertThat(this.validator.validate(schema, s("name", "n")).valid()).isTrue();
		assertThat(this.validator.validate(schema, s("credit_card", "1234", "billing_address", "here")).valid())
			.isTrue();
		assertThat(this.validator.validate(schema, s("credit_card", "1234")).valid()).isFalse();
	}

	@Test
	void containsWithBounds() {
		var schema = s("type", "array", "contains", s("const", "x"), "minContains", 1, "maxContains", 2);
		assertThat(this.validator.validate(schema, List.of("x", "y")).valid()).isTrue();
		assertThat(this.validator.validate(schema, List.of("y")).valid()).isFalse();
		assertThat(this.validator.validate(schema, List.of("x", "x", "x")).valid()).isFalse();
	}

	@Test
	void dynamicRefAndAnchor() {
		var defs = s("node", s("$dynamicAnchor", "node", "anyOf",
				List.of(s("type", "string"), s("type", "object", "additionalProperties", s("$dynamicRef", "#node")))));
		var schema = s("$ref", "#/$defs/node", "$defs", defs);
		assertThat(this.validator.validate(schema, s("child", s("leaf", "v"))).valid()).isTrue();
		assertThat(this.validator.validate(schema, s("child", s("leaf", 42))).valid()).isFalse();
	}

	@Test
	void propertyNamesPattern() {
		var schema = s("type", "object", "propertyNames", s("pattern", "^cfg_"));
		assertThat(this.validator.validate(schema, s("cfg_a", 1)).valid()).isTrue();
		assertThat(this.validator.validate(schema, s("bad_name", 1)).valid()).isFalse();
	}

	@Test
	void numericFormsAndConstEnum() {
		var schema = s("type", "number", "minimum", 0, "exclusiveMaximum", 10, "multipleOf", 2);
		assertThat(this.validator.validate(schema, 8).valid()).isTrue();
		assertThat(this.validator.validate(schema, 10).valid()).isFalse();
		assertThat(this.validator.validate(schema, 7).valid()).isFalse();
		var constSchema = s("const", List.of(1, 2));
		assertThat(this.validator.validate(constSchema, List.of(1, 2)).valid()).isTrue();
		// A String argument is parsed as a serialized JSON document, not taken as a
		// literal JSON string value: pass quoted text ("\"red\"") for a root-level
		// string instance.
		var enumSchema = s("enum", List.of("red", "green"));
		assertThat(this.validator.validate(enumSchema, "\"red\"").valid()).isTrue();
		assertThat(this.validator.validate(enumSchema, "\"blue\"").valid()).isFalse();
		var numericEnumSchema = s("enum", List.of(1, 2));
		assertThat(this.validator.validate(numericEnumSchema, 1).valid()).isTrue();
		assertThat(this.validator.validate(numericEnumSchema, 3).valid()).isFalse();
	}

	@Test
	void defsAndLocalRef() {
		var schema = s("type", "object", "properties", s("a", s("$ref", "#/$defs/str")), "$defs",
				s("str", s("type", "string")));
		assertThat(this.validator.validate(schema, s("a", "ok")).valid()).isTrue();
		assertThat(this.validator.validate(schema, s("a", 3)).valid()).isFalse();
	}

	@Test
	void metaSchemaRejectsStructurallyInvalidSchema() {
		var response = this.validator.validateSchema(s("type", "object", "required", "not-an-array"));
		assertThat(response.valid()).isFalse();
	}

	@Test
	void non202012DialectDeclarationSkipsMetaValidation() {
		var schema = s("$schema", "http://json-schema.org/draft-07/schema#", "type", "object", "required",
				"draft07-allows-this-shape-anyway");
		var response = this.validator.validateSchema(schema);
		assertThat(response.valid()).isTrue();
	}

}
