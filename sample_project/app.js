const child_process = require('child_process');
const apiKey = 'hardcoded-node-token';
function run(input) {
  child_process.exec('dir ' + input);
  document.body.innerHTML = input;
}
