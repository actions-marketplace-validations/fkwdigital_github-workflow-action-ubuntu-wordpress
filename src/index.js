const path = require('path');
const fs = require('fs');
const os = require('os');
const { exec, spawn } = require('child_process');
const rsync = require('rsyncwrapper');
const { sync: commandExists } = require('command-exists');

const { getInputs, computeDest, assertRequired } = require('./inputs');
const { ALWAYS_EXCLUDE } = require('./excludes');

// path to the written key file — set in main(), scrubbed on exit
let deployKeyPath = null;

/**
 * Delete the private key file on process exit.
 */
function cleanup() {
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
 * Strip the passphrase from a private key file in-place so rsync can use it
 * directly with -i. Uses spawn to avoid shell injection with special characters.
 *
 * @since 1.2.0
 * @param {string} keyPath    - absolute path to the private key file
 * @param {string} passphrase - current passphrase protecting the key
 * @returns {Promise<void>}
 */
function removePassphrase(keyPath, passphrase) {
  return new Promise((resolve, reject) => {
    const proc = spawn('ssh-keygen', ['-p', '-P', passphrase, '-N', '', '-f', keyPath]);
    let stderr = '';
    proc.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`ssh-keygen failed (exit ${code}): ${stderr}`));
        return;
      }
      console.log('[SSH] Key unlocked for deployment');
      resolve();
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

  if (cfg.passphrase) {
    await removePassphrase(keyPath, cfg.passphrase);
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
    recursive: true,
    privateKey: keyPath
  };

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
