// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 45_000,
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'retain-on-failure'
  },
  projects: [
    {
      name: 'desktop',
      use: { browserName: 'chromium', viewport: { width: 1440, height: 1000 } }
    },
    {
      name: 'tablet',
      use: {
        browserName: 'chromium',
        viewport: { width: 834, height: 1194 },
        deviceScaleFactor: 2,
        hasTouch: true,
        isMobile: false
      }
    },
    {
      name: 'phone',
      use: {
        browserName: 'chromium',
        viewport: { width: 412, height: 915 },
        deviceScaleFactor: 2.625,
        hasTouch: true,
        isMobile: true
      }
    },
    {
      name: 'narrow',
      use: { browserName: 'chromium', viewport: { width: 320, height: 740 } }
    }
  ],
  outputDir: 'test-results/playwright'
});
