import { execSync as run } from 'node:child_process';
run('whoami', { stdio: 'ignore' });
