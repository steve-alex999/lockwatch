const cp = require("child_process");
cp.exec("id", function () {
  // Unbalanced on purpose: this file does not parse.
  if (true {
});
