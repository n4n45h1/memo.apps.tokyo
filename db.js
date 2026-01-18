import sqlite3 from 'sqlite3';
import { promisify } from 'util';

const db = new sqlite3.Database('./memos.db');

db.run = promisify(db.run);
db.get = promisify(db.get);
db.all = promisify(db.all);

await db.run(`
  CREATE TABLE IF NOT EXISTS memos (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    password TEXT,
    created_at INTEGER NOT NULL
  )
`);

export default db;
