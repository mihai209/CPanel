import fs from 'fs/promises';
import path from 'path';
import { build } from 'esbuild';

const rootDir = process.cwd();
const sourceDir = path.join(rootDir, 'views', 'react');
const outputDir = path.join(rootDir, 'public', 'react-build');

await fs.mkdir(outputDir, { recursive: true });

const entries = (await fs.readdir(sourceDir))
    .filter((name) => name.endsWith('.jsx'))
    .map((name) => ({
        source: path.join(sourceDir, name),
        output: path.join(outputDir, `${name.replace(/\.jsx$/i, '')}.js`)
    }));

if (entries.length === 0) {
    console.log('[build:react] No React entries found under views/react');
    process.exit(0);
}

for (const entry of entries) {
    await build({
        entryPoints: [entry.source],
        outfile: entry.output,
        bundle: true,
        minify: false,
        sourcemap: false,
        platform: 'browser',
        target: ['es2020'],
        format: 'iife',
        jsx: 'automatic',
        logLevel: 'info',
        define: {
            'process.env.NODE_ENV': '"production"'
        }
    });
    console.log(`[build:react] Built ${path.basename(entry.source)} -> ${path.relative(rootDir, entry.output)}`);
}
