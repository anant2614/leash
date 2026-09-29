const test = require("node:test");
const assert = require("node:assert");
const { slugify } = require("../src/slugify");

test("basic", () => assert.strictEqual(slugify("Hello World"), "hello-world"));
test("collapses separators", () => assert.strictEqual(slugify("Hello,  World!"), "hello-world"));
test("trims edges", () => assert.strictEqual(slugify("  --Hi--  "), "hi"));
