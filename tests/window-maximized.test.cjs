const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const configPath = path.join(__dirname, '..', 'src-tauri', 'tauri.conf.json');
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const mainWindow = config.app.windows.find((window) => window.label === 'main');

test('main window starts maximized without entering fullscreen', () => {
  assert.ok(mainWindow, 'Tauri config defines the main window');
  assert.equal(mainWindow.maximized, true);
  assert.notEqual(mainWindow.fullscreen, true);
  assert.equal(mainWindow.resizable, true);
});
