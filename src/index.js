const path = require('path');
const fs = require('fs');
const os = require('os');
const { exec } = require('child_process');
const rsync = require('rsyncwrapper');
const { sync: commandExists } = require('command-exists');

const { getInputs, computeDest, assertRequired } = require('./inputs');
const { ALWAYS_EXCLUDE } = require('./excludes');

// path to the written key file — set in main(), scrubbed on exit
let deployKeyPath = null;

/**
 * Kill ssh-agent and delete the private key file on process exit.
 */
function cleanup() {
  const pid = process.env.SSH_AGENT_PID;
  if (pid) {
    try {
      process.kill(parseInt(pid, 10));
    } catch (e) {
      /* already gone */
    }
  }
  if (deployKeyPath) {
    try {
      fs.unlinkSync(deployKeyPath);
    } catch (e) {
      /* already gone */
    }
  }
}
process.on('exit', cleanup);

/**
 * Start ssh-agent, add a passphrase-protected key, and set
 * SSH_AUTH_SOCK / SSH_AGENT_PID in the current process env
 * so child processes (rsync → ssh) inherit it automatically.
 */
function startSshAgent(keyPath, passphrase) {
  return new Promise((resolve, reject) => {
    exec('ssh-agent -s', (err, stdout) => {
      if (err) {
        return reject(new Error(`ssh-agent start failed: ${err.message}`));
      }

      const [, authSock] = stdout.match(/SSH_AUTH_SOCK=([^;]+)/) || [];
      const [, agentPid] = stdout.match(/SSH_AGENT_PID=(\d+)/) || [];

      if (!authSock) {
        return reject(new Error('Failed to parse SSH_AUTH_SOCK from ssh-agent output'));
      }

      process.env.SSH_AUTH_SOCK = authSock;
      if (agentPid) {
        process.env.SSH_AGENT_PID = agentPid;
      }

      const ppFile = path.join(os.tmpdir(), `pp_${process.pid}`);
      const askpass = path.join(os.tmpdir(), `askpass_${process.pid}.sh`);

      fs.writeFileSync(ppFile, passphrase, { mode: 0o600 });
      fs.writeFileSync(askpass, `#!/bin/sh\ncat "${ppFile}"\n`, { mode: 0o700 });

      const addEnv = {
        ...process.env,
        SSH_ASKPASS: askpass,
        SSH_ASKPASS_REQUIRE: 'force',
        DISPLAY: ':0'
      };

      return exec(`ssh-add "${keyPath}"`, { env: addEnv }, (addErr, _, addStderr) => {
        try {
          fs.unlinkSync(ppFile);
        } catch (e) {
          /* ignore */
        }
        try {
          fs.unlinkSync(askpass);
        } catch (e) {
          /* ignore */
        }

        if (addErr) {
          reject(new Error(`ssh-add failed: ${addErr.message}\n${addStderr || ''}`));
          return;
        }

        console.log('✅ [SSH] Key added to ssh-agent');
        resolve();
      });
    });
  });
}

function ensureRsync() {
  return new Promise((resolve, reject) => {
    if (commandExists('rsync')) {
      resolve();
      return;
    }
    exec('sudo apt-get update && sudo apt-get --no-install-recommends install -y rsync', (err) => {
      if (err) {
        reject(new Error(`rsync install failed: ${err.message}`));
        return;
      }
      resolve();
    });
  });
}

function readExcludeFile(workspace, relPath) {
  if (!relPath) return [];
  const p = path.isAbsolute(relPath) ? relPath : path.join(workspace, relPath);
  if (!fs.existsSync(p)) return [];
  return fs
    .readFileSync(p, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function splitArgsPreserveQuotes(str) {
  const tokens = (str || '').match(/(?:[^\s'"]+|'[^']*'|"[^"]*")+/g) || [];
  return tokens.map((t) => t.replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1'));
}

function validateDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function validateFile(filePath) {
  if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, '', { encoding: 'utf8', mode: 0o600 });
}
function addSshKey(key, name) {
  const home = process.env.HOME || os.homedir();
  const sshDir = path.join(home, '.ssh');
  validateDir(sshDir);
  validateFile(path.join(sshDir, 'known_hosts'));
  const filePath = path.join(sshDir, name || 'deploy_key');
  fs.writeFileSync(filePath, key, { encoding: 'utf8', mode: 0o600 });
  return filePath;
}

/**
 * Append known_hosts content to ~/.ssh/known_hosts so ssh can verify the
 * remote host fingerprint. Obtain the value via: ssh-keyscan -H <host>
 *
 * @since 1.1.0
 * @param {string} knownHosts - raw known_hosts lines from ssh-keyscan
 * @param {string} sshDir     - absolute path to the .ssh directory
 * @returns {void}
 */
function writeKnownHosts(knownHosts, sshDir) {
  const knownHostsPath = path.join(sshDir, 'known_hosts');
  const entry = knownHosts.endsWith('\n') ? knownHosts : `${knownHosts}\n`;
  fs.appendFileSync(knownHostsPath, entry, { encoding: 'utf8', mode: 0o600 });
  console.log('[SSH] known_hosts written — strict host key verification enabled');
}

async function main() {
  const cfg = getInputs();
  assertRequired(cfg);

  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const remoteDest = `${cfg.user}@${cfg.host}:${computeDest(cfg)}`;
  const localSrc = `${path.posix.join(workspace, cfg.source)}/`;
  const fileEx = readExcludeFile(workspace, cfg.excludeFile);
  const extra = (cfg.extraExclude || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const EXCLUDES = [...ALWAYS_EXCLUDE, ...fileEx, ...extra];

  console.log(`[deploy] Source → ${localSrc}`);
  console.log(`[deploy] Dest → ${remoteDest}`);
  console.log(`[deploy] Rsync → ${cfg.rsyncArgs}`);
  console.log(`[deploy] Excludes → ${EXCLUDES.length}`);

  const home = process.env.HOME || os.homedir();
  const sshDir = path.join(home, '.ssh');

  const keyPath = addSshKey(cfg.key, cfg.keyName);
  deployKeyPath = keyPath;

  if (cfg.knownHosts) {
    writeKnownHosts(cfg.knownHosts, sshDir);
  } else {
    console.warn(
      '⚠️  [SSH] KNOWN_HOSTS is not set — host key verification is disabled.' +
        ' Set KNOWN_HOSTS (via ssh-keyscan -H <host>) to protect against MITM attacks.'
    );
  }

  const strictHostChecking = cfg.knownHosts ? 'yes' : 'no';
  const useAgent = !!cfg.passphrase;

  if (useAgent) {
    await startSshAgent(keyPath, cfg.passphrase);
    console.log('[deploy] Using ssh-agent (passphrase-protected key)');
  }

  await ensureRsync();

  const rsyncOpts = {
    src: localSrc,
    dest: remoteDest,
    args: splitArgsPreserveQuotes(cfg.rsyncArgs),
    port: cfg.port,
    excludeFirst: EXCLUDES,
    ssh: true,
    sshCmdArgs: ['-o', `StrictHostKeyChecking=${strictHostChecking}`],
    recursive: true
  };

  if (!useAgent) {
    rsyncOpts.privateKey = keyPath;
  }

  rsync(rsyncOpts, (error, stdout, stderr, cmd) => {
    if (error) {
      console.error('⚠️  [rsync] error:', error.message);
      console.error('stderr:', stderr || '');
      console.error('cmd:', cmd || '');
      process.exit(1);
      return;
    }
    console.log('✅ [rsync] completed');
    if (stdout) console.log(stdout);
    process.exit(0);
  });
}

main();
