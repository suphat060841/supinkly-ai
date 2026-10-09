const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const gitObjectsDir = path.join(__dirname, '..', '.git', 'objects');

function inspectObject(rel) {
    const p = path.join(gitObjectsDir, rel);
    if (!fs.existsSync(p)) return console.log('Not found:', rel);
    try {
        const compressed = fs.readFileSync(p);
        console.log(`File ${rel}: compressed size = ${compressed.length}`);
        const decompressed = zlib.inflateSync(compressed);
        const nullIdx = decompressed.indexOf(0);
        const header = decompressed.slice(0, nullIdx).toString('utf8');
        const content = decompressed.slice(nullIdx + 1);
        console.log(`  Header: ${header}`);
        console.log(`  Decompressed size: ${content.length}`);
        const sample = content.slice(0, 200).toString('utf8');
        console.log(`  Sample: ${sample.replace(/\n/g, '\\n')}`);
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
}

inspectObject('27/9cab1a8288e10b493f1250733f7879314d798c');
inspectObject('4d/64c6fcb6ec066d18f4f4bd7565d7831738d4eb');
inspectObject('c7/420a08134d4ef687a9e199dfa12c755150be63');
