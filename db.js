// db.js
const path    = require('path');
const sqlite3 = require('@vscode/sqlite3').verbose();   // <- compatível Node 23+

const dbPath  = path.resolve(process.env.DB_PATH || 'database.db');

const db = new sqlite3.Database(
  dbPath,
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) throw err;
    console.log('📂  SQLite conectado em', dbPath);
  }
);

module.exports = { db };
