const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const configPath = path.join(__dirname, '..', 'src-tauri', 'tauri.conf.json');
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const mainWindow = config.app.windows.find((window) => window.label === 'main');
const backendPath = path.join(__dirname, '..', 'src-tauri', 'src', 'lib.rs');
const backend = readFileSync(backendPath, 'utf8');

test('main window starts maximized without entering fullscreen', () => {
  assert.ok(mainWindow, 'Tauri config defines the main window');
  assert.equal(mainWindow.maximized, true);
  assert.notEqual(mainWindow.fullscreen, true);
  assert.equal(mainWindow.resizable, true);
});

test('key-login activation only restores the window when it is minimized', () => {
  assert.ok(
    /let minimized_before = unsafe\s*\{\s*IsIconic\(hwnd\.0\)\s*!=\s*0\s*\};[\s\S]{0,160}restore_window_if_minimized\(minimized_before,/.test(backend),
    'a maximized (non-minimized) window must not receive SW_RESTORE before key login',
  );
});
