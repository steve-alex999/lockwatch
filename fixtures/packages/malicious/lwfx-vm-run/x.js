const vm = require('vm');
const parts = ['console', '.log', '("lockwatch fixture")'];
vm.runInNewContext(parts.join(''), { console });
