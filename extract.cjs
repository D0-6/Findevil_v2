const fs = require('fs');
const path = require('path');
const unzipper = require('unzipper');

const zipPath = path.join(process.cwd(), 'src', 'Findevil_new', 'find_evil_complete.zip');
const destPath = path.join(process.cwd(), 'src', 'Findevil_new', 'extracted');

fs.createReadStream(zipPath)
  .pipe(unzipper.Extract({ path: destPath }))
  .on('close', () => console.log('Extracted successfully.'))
  .on('error', err => console.error('Error:', err));
