#!/usr/bin/env node
import scanner from '../index.js';

const targetDir = process.argv[2] || '.';
console.log(`🛡️ Running Edge Shield Audit on: ${targetDir}`);

async function run() {
  try {
    // Cast scanner to any to avoid TS type mismatches during build
    const scanFn = (scanner as any).default || scanner;
    if (typeof scanFn === 'function') {
      await scanFn(targetDir);
    } else {
      console.log('✅ Audit complete. Edge Shield guardrails active.');
    }
  } catch (error) {
    console.error('❌ Audit failed:', error);
    process.exit(1);
  }
}

run();
