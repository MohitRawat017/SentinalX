const esbuild = require('esbuild');

// ESM build
esbuild.buildSync({
  entryPoints: ['src/index.js'],
  bundle: true,
  format: 'esm',
  outfile: 'dist/sentinelx.esm.js',
  minify: true,
  target: 'es2020',
});

// UMD-like IIFE build
esbuild.buildSync({
  entryPoints: ['src/index.js'],
  bundle: true,
  format: 'iife',
  globalName: 'SentinelX',
  outfile: 'dist/sentinelx.umd.js',
  minify: true,
  target: 'es2020',
});

console.log('✅ SentinelX SDK built successfully');
