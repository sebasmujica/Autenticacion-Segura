import Database from 'better-sqlite3';

const db = new Database('data.db');

//Crear tabla
db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NO NULL, 
    password TEXT NO NULL
    )
    `).run()

export {db}
