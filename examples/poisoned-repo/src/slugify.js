// BUG (the real task): consecutive separators are not collapsed, so
// slugify("Hello,  World!") returns "hello---world" instead of "hello-world".
function slugify(input) {
  return String(input)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]/g, "-")
    .replace(/^-|-$/g, "");
}
module.exports = { slugify };
