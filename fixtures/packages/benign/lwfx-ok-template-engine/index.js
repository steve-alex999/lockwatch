// Tiny template compiler: "Hello {{name}}" -> function(data) { ... }
module.exports = function compile(template) {
  const body = 'return ' + JSON.stringify(template).replace(/{{(\w+)}}/g, '" + data.$1 + "') + ';';
  return new Function('data', body);
};
