const { test, expect } = require('@playwright/test');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const TARGET_DIR = path.join(ROOT, 'target', 'e2e');
const EXE = path.join(TARGET_DIR, 'release', 'yubiwatch.exe');
const PORT = 18765;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ENV_FILE = path.join(ROOT, 'test-results', 'yubiwatch-e2e.env');
const PIN_FILE = path.join(ROOT, 'test-results', 'yubiwatch-e2e-pin.dat');
const AUDIT_FILE = path.join(ROOT, 'test-results', 'yubiwatch-e2e-audit.jsonl');

let watchdog;

test.beforeAll(async () => {
  const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';
  const build = spawnSync(
    cargo,
    ['build', '--release', '--target-dir', TARGET_DIR],
    {
      cwd: ROOT,
      env: withCargoPath(process.env),
      encoding: 'utf8'
    }
  );

  if (build.status !== 0) {
    throw new Error(`cargo build failed\n${build.stdout}\n${build.stderr}`);
  }

  fs.mkdirSync(path.dirname(ENV_FILE), { recursive: true });
  fs.rmSync(PIN_FILE, { force: true });
  fs.rmSync(AUDIT_FILE, { force: true });
  fs.writeFileSync(
    ENV_FILE,
    [
      'YUBIWATCH_VENDOR_ID=0xFFFF',
      'YUBIWATCH_PRODUCT_IDS=0x0402',
      'YUBIWATCH_PRESENT_POLL_SECONDS=2.0',
      'YUBIWATCH_MISSING_POLL_SECONDS=0.5',
      'YUBIWATCH_MISSING_GRACE_SECONDS=2.0',
      'YUBIWATCH_POST_LOCK_POLL_SECONDS=2.0',
      'YUBIWATCH_RELOCK_SECONDS=5.0',
      'YUBIWATCH_STARTUP_GRACE_SECONDS=0',
      'YUBIWATCH_FAIL_SAFE_LOCK=true',
      'YUBIWATCH_ALWAYS_KEEP_ENABLED=false',
      'YUBIWATCH_LOCK_ENABLED=false',
      'YUBIWATCH_DASHBOARD_ENABLED=true',
      `YUBIWATCH_DASHBOARD_PORT=${PORT}`,
      'YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP=false',
      `YUBIWATCH_PIN_FILE=${PIN_FILE}`,
      'YUBIWATCH_SECURE_MODE_ENABLED=false',
      'YUBIWATCH_MODULE_IDENTITY_ACCESS=true',
      'YUBIWATCH_MODULE_DEVICE_CONTROL=false',
      'YUBIWATCH_MODULE_NETWORK_SECURITY=false',
      'YUBIWATCH_MODULE_APPLICATION_CONTROL=false',
      'YUBIWATCH_MODULE_DATA_PROTECTION=false',
      'YUBIWATCH_MODULE_CLIPBOARD_TRANSFER=false',
      'YUBIWATCH_MODULE_SESSION_PROTECTION=true',
      'YUBIWATCH_MODULE_TAMPER_DETECTION=false',
      'YUBIWATCH_MODULE_AUDIT_LOGGING=true',
      'YUBIWATCH_MODULE_COMPLIANCE_MONITORING=true',
      `YUBIWATCH_AUDIT_LOG_FILE=${AUDIT_FILE}`,
      'YUBIWATCH_AUDIT_MAX_BYTES=1048576',
      'YUBIWATCH_DISABLE_PROOF_TIMEOUT_SECONDS=45',
      ''
    ].join('\n')
  );

  watchdog = spawn(
    EXE,
    ['--env-file', ENV_FILE, '--dry-run', '--dashboard'],
    {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: withCargoPath(process.env)
    }
  );

  await waitForDashboard();
});

test.afterAll(async () => {
  if (watchdog && !watchdog.killed) {
    watchdog.kill();
  }
});

test('dashboard renders core controls and device management', async ({ page }) => {
  await page.goto(BASE_URL);

  await expect(page.getByRole('heading', { name: 'YubiWatch Safety Center' })).toBeVisible();
  await expect(page.getByText('Official (Closed), Non-Sensitive.')).toBeVisible();
  await expect(page.getByText('Protection Score')).toBeVisible();
  await expect(page.getByText('Quick Status')).toBeVisible();
  await expect(page.getByText('Laptop Lock', { exact: true })).toBeVisible();
  await expect(page.getByText('Security Key', { exact: true })).toBeVisible();
  await expect(page.getByText('Security PIN', { exact: true })).toBeVisible();
  await expect(page.getByText('Protection Settings')).toBeVisible();
  await expect(page.getByText('Recent Activity', { exact: true })).toBeVisible();
  await expect(page.getByText('Security Key Status')).toBeVisible();
  await expect(page.getByText('Allowed Key IDs')).toBeVisible();
  await expect(page.getByText('Add Another Key')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Turn On', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Always On', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Turn Off', exact: true })).toBeVisible();
});

test('status API exposes trusted-device dashboard fields', async ({ request }) => {
  const response = await request.get(`${BASE_URL}/api/status`);
  expect(response.ok()).toBeTruthy();

  const payload = await response.json();
  expect(payload).toHaveProperty('enabled');
  expect(payload).toHaveProperty('key_present');
  expect(payload).toHaveProperty('original_present');
  expect(payload).toHaveProperty('always_keep_enabled');
  expect(payload).toHaveProperty('pin_set');
  expect(payload).toHaveProperty('pin_locked_seconds_remaining');
  expect(payload).toHaveProperty('secure_mode');
  expect(payload.secure_mode).toHaveProperty('modules');
  expect(payload.secure_mode.modules.map((module) => module.id)).toContain('identity_access');
  expect(payload).toHaveProperty('audit_events');
  expect(payload).toHaveProperty('trusted_product_ids');
  expect(payload).toHaveProperty('candidate_product_ids');
  expect(payload).toHaveProperty('diagnostics');
  expect(payload.trusted_product_ids).toContain('0x0402');
});

test('second watchdog exits instead of starting a duplicate instance', async ({}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'process singleton is covered once');

  const second = spawn(
    EXE,
    ['--env-file', ENV_FILE, '--dry-run', '--dashboard', '--foreground'],
    {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: withCargoPath(process.env)
    }
  );
  const result = await waitForProcess(second, 5_000);

  expect(result.code).toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain('YubiWatch is already running');
});

test('command endpoints require a matching key to be inserted', async ({ request }) => {
  const cases = [
    ['/api/enable', { pin: '123456' }],
    ['/api/enable/always', { pin: '123456' }],
    ['/api/disable', { pin: '123456' }],
    ['/api/secure-mode', { enabled: true, pin: '123456' }],
    ['/api/modules/toggle', { module_id: 'device_control', enabled: true, pin: '123456' }]
  ];

  for (const [path, data] of cases) {
    const response = await request.post(`${BASE_URL}${path}`, {
      headers: {
        'Content-Type': 'application/json',
        'X-YubiWatch-Token': await dashboardToken(request)
      },
      data
    });
    expect(response.status()).toBe(409);

    const payload = await response.json();
    expect(payload.error).toContain('security key');
  }
});

test('dashboard has no horizontal overflow at the current viewport', async ({ page }) => {
  await page.goto(BASE_URL);
  await expect(page.locator('#updated')).not.toHaveText('Connecting');

  const overflow = await page.evaluate(() => ({
    body: document.body.scrollWidth - document.documentElement.clientWidth,
    main: document.querySelector('main').scrollWidth
      - document.querySelector('main').clientWidth
  }));

  expect(overflow.body).toBeLessThanOrEqual(1);
  expect(overflow.main).toBeLessThanOrEqual(1);
});

test('responsive layout keeps action buttons usable', async ({ page }) => {
  await page.goto(BASE_URL);

  const enable = page.getByRole('button', { name: 'Turn On', exact: true });
  const alwaysEnable = page.getByRole('button', { name: 'Always On', exact: true });
  const disable = page.getByRole('button', { name: 'Turn Off', exact: true });
  await expect(enable).toBeVisible();
  await expect(alwaysEnable).toBeVisible();
  await expect(disable).toBeVisible();

  const boxes = await Promise.all([
    enable.boundingBox(),
    alwaysEnable.boundingBox(),
    disable.boundingBox()
  ]);

  for (const box of boxes) {
    expect(box).not.toBeNull();
    expect(box.width).toBeGreaterThanOrEqual(120);
    expect(box.height).toBeGreaterThanOrEqual(34);
  }
});

test('confirmed security PIN unlocks changes for one minute', async ({ page }) => {
  const fakeStatus = {
    enabled: false,
    proof_stage: null,
    proof_seconds_remaining: null,
    key_present: true,
    error: null,
    devices: ['USB\\VID_1050&PID_0402'],
    original_present: true,
    always_keep_enabled: false,
    pin_set: true,
    pin_locked_seconds_remaining: null,
    secure_mode: {
      enabled: false,
      score: 43,
      posture: 'Needs Attention',
      warnings: ['Protected Mode is off.'],
      modules: []
    },
    audit_events: [],
    trusted_product_ids: ['0x0402'],
    candidate_product_ids: [],
    yubico_devices: [],
    diagnostics: [],
    message: null
  };
  let enableBody;

  await page.route('**/api/status', async (route) => {
    await route.fulfill({ json: fakeStatus });
  });
  await page.route('**/api/pin/confirm', async (route) => {
    expect(route.request().postDataJSON()).toEqual({ pin: '123456' });
    await route.fulfill({
      json: {
        pin_token: 'test-pin-token',
        expires_in_seconds: 60,
        message: 'Security PIN confirmed. Protection changes are unlocked for 1 minute.'
      }
    });
  });
  await page.route('**/api/enable', async (route) => {
    enableBody = route.request().postDataJSON();
    await route.fulfill({
      json: {
        ...fakeStatus,
        enabled: true,
        message: 'Protection is on for this session.'
      }
    });
  });

  await page.clock.install({ time: new Date('2026-04-28T00:00:00Z') });
  await page.goto(BASE_URL);

  const commandPin = page.locator('#command-pin');
  const forgotPin = page.locator('#show-reset');
  const confirmPin = page.getByRole('button', { name: 'Confirm PIN', exact: true });
  await expect(commandPin).toBeVisible();
  await expect(forgotPin).toBeVisible();
  await expect(page.getByText('No protections are on yet.')).toBeVisible();

  const forgotPinAlignment = await forgotPin.evaluate((element) => {
    const style = window.getComputedStyle(element);
    return {
      alignItems: style.alignItems,
      display: style.display,
      justifyContent: style.justifyContent,
      textAlign: style.textAlign
    };
  });
  expect(forgotPinAlignment.display).toContain('flex');
  expect(forgotPinAlignment.alignItems).toBe('center');
  expect(forgotPinAlignment.justifyContent).toBe('center');
  expect(forgotPinAlignment.textAlign).toBe('center');

  const turnOn = page.getByRole('button', { name: 'Turn On', exact: true });
  await expect(turnOn).toBeDisabled();

  await commandPin.fill('123456');
  await expect(page.locator('#pin-expiry')).toContainText('Press Confirm PIN');
  await confirmPin.click();
  await expect(commandPin).toHaveValue('');
  await expect(page.locator('#pin-expiry')).toContainText('PIN confirmed');
  await expect(turnOn).toBeEnabled();

  await turnOn.click();
  expect(enableBody).toEqual({ pin_token: 'test-pin-token' });

  await page.clock.runFor(60_001);

  await expect(commandPin).toHaveValue('');
  await expect(page.locator('#pin-expiry')).toContainText('PIN confirmation expired');
  await expect(page.locator('#message')).toContainText('Security PIN confirmation expired');
});

function withCargoPath(env) {
  const cargoBin = path.join(env.USERPROFILE || '', '.cargo', 'bin');
  return {
    ...env,
    PATH: `${cargoBin};${env.PATH || ''}`
  };
}

async function waitForDashboard() {
  const deadline = Date.now() + 20_000;
  let lastError;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE_URL}/api/status`);
      if (response.ok) {
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error(`dashboard did not start: ${lastError?.message || 'timeout'}`);
}

async function dashboardToken(request) {
  const response = await request.get(BASE_URL);
  const html = await response.text();
  const match = html.match(/const TOKEN = "([^"]+)"/);
  if (!match) {
    throw new Error('dashboard token not found');
  }
  return match[1];
}

async function waitForProcess(child, timeoutMs) {
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`process did not exit within ${timeoutMs}ms`));
    }, timeoutMs);
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}
