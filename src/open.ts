/**
 * Open the report in the default browser. The ONLY subprocess this tool ever
 * spawns — and the argument is the local report path. `--no-open` skips it.
 */
import { spawn } from 'node:child_process';

export function openInBrowser(filePath: string): boolean {
  try {
    let cmd: string;
    let args: string[];
    if (process.platform === 'win32') {
      cmd = 'cmd';
      args = ['/c', 'start', '', filePath];
    } else if (process.platform === 'darwin') {
      cmd = 'open';
      args = [filePath];
    } else {
      cmd = 'xdg-open';
      args = [filePath];
    }
    const child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => {
      /* best effort — the path is printed either way */
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}
