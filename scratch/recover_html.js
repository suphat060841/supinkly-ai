const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const gitObjectsDir = path.join(__dirname, '..', '.git', 'objects');
const subdirs = fs.readdirSync(gitObjectsDir);

console.log('Searching git objects for full index.html snapshot...');

let bestBlob = null;
let maxLines = 0;

for (const sub of subdirs) {
    const fullSub = path.join(gitObjectsDir, sub);
    if (!fs.statSync(fullSub).isDirectory() || sub === 'info' || sub === 'pack') continue;
    const files = fs.readdirSync(fullSub);
    for (const f of files) {
        const filePath = path.join(fullSub, f);
        try {
            const compressed = fs.readFileSync(filePath);
            const decompressed = zlib.inflateSync(compressed);
            const nullIdx = decompressed.indexOf(0);
            const header = decompressed.slice(0, nullIdx).toString('utf8');
            const content = decompressed.slice(nullIdx + 1);

            if (header.startsWith('blob')) {
                const text = content.toString('utf8');
                if (text.includes('<!DOCTYPE html>') || text.includes('Supinkly.AI')) {
                    const lines = text.split('\n').length;
                    console.log(`Found HTML Blob ${sub}${f.slice(0, 8)}: lines=${lines}, bytes=${content.length}`);
                    if (lines > maxLines) {
                        maxLines = lines;
                        bestBlob = { id: `${sub}${f}`, lines, bytes: content.length, text };
                    }
                }
            }
        } catch (e) {
            // ignore non-zlib or invalid objects
        }
    }
}

if (bestBlob && bestBlob.lines > 3000) {
    console.log(`\nSUCCESS! Found best snapshot ${bestBlob.id} with ${bestBlob.lines} lines (${bestBlob.bytes} bytes).`);
    const recoveredPath = path.join(__dirname, 'recovered_index.html');
    fs.writeFileSync(recoveredPath, bestBlob.text, 'utf8');
    console.log(`Saved recovered file to: ${recoveredPath}`);

    // Backup current 1888-line file
    const indexPath = path.join(__dirname, '..', 'index.html');
    fs.writeFileSync(path.join(__dirname, 'index.html.broken.bak'), fs.readFileSync(indexPath));

    // Restore directly to index.html
    fs.writeFileSync(indexPath, bestBlob.text, 'utf8');
    console.log(`Restored full ${bestBlob.lines}-line file directly to: ${indexPath}`);
} else {
    console.log('\nNo snapshot with > 3000 lines found in git objects.');
}
