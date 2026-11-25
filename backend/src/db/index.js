const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const config = require('../config');

const uuidv4 = () => crypto.randomUUID();

let pool = null;
let isPostgresConnected = false;

// Embedded local store path for zero-friction fallback
const LOCAL_DB_PATH = path.resolve(__dirname, '../../storage/database.json');

// Memory representation for local fallback
let localDb = {
  users: [],
  documents: [],
  document_access: [],
  access_logs: [],
  sessions: [],
};

function loadLocalDb() {
  const dir = path.dirname(LOCAL_DB_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (fs.existsSync(LOCAL_DB_PATH)) {
    try {
      const data = fs.readFileSync(LOCAL_DB_PATH, 'utf8');
      localDb = JSON.parse(data);
    } catch (err) {
      console.warn('[Database] Local database file corrupt or unreadable, initializing fresh state.');
    }
  } else {
    saveLocalDb();
  }
}

function saveLocalDb() {
  const dir = path.dirname(LOCAL_DB_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(LOCAL_DB_PATH, JSON.stringify(localDb, null, 2), 'utf8');
}

/**
 * Universal query runner:
 * If PostgreSQL is active, executes via PG Pool.
 * Otherwise, executes via local relational store supporting SQL operations.
 */
async function query(sqlText, params = []) {
  if (isPostgresConnected && pool) {
    try {
      const res = await pool.query(sqlText, params);
      return res;
    } catch (err) {
      console.error('[PostgreSQL Error]', err.message);
      throw err;
    }
  }

  // Fallback local SQL emulator
  return runLocalQuery(sqlText, params);
}

/**
 * Local relational query engine supporting standard parameterized queries
 */
function runLocalQuery(sqlText, params = []) {
  const cleanSql = sqlText.trim().replace(/--.*$/gm, '').trim();
  const lowerSql = cleanSql.toLowerCase();

  // Handle BEGIN, COMMIT, ROLLBACK
  if (lowerSql === 'begin' || lowerSql === 'commit' || lowerSql === 'rollback') {
    return { rows: [], rowCount: 0 };
  }

  // 1. SELECT
  if (lowerSql.startsWith('select')) {
    return executeLocalSelect(cleanSql, params);
  }

  // 2. INSERT
  if (lowerSql.startsWith('insert into')) {
    return executeLocalInsert(cleanSql, params);
  }

  // 3. UPDATE
  if (lowerSql.startsWith('update')) {
    return executeLocalUpdate(cleanSql, params);
  }

  // 4. DELETE
  if (lowerSql.startsWith('delete from')) {
    return executeLocalDelete(cleanSql, params);
  }

  return { rows: [], rowCount: 0 };
}

function executeLocalSelect(sql, params) {
  loadLocalDb();
  const lower = sql.toLowerCase();

  // Match table name
  const fromMatch = sql.match(/from\s+([a-zA-Z0-9_]+)(\s+(as\s+)?([a-zA-Z0-9_]+))?/i);
  if (!fromMatch) return { rows: [], rowCount: 0 };

  const tableName = fromMatch[1].toLowerCase();
  let table = localDb[tableName] ? [...localDb[tableName]] : [];

  // Check JOIN with optional table alias
  const joinMatch = sql.match(/join\s+([a-zA-Z0-9_]+)(?:\s+(?:as\s+)?([a-zA-Z0-9_]+))?\s+on\s+([a-zA-Z0-9_\.]+)\s*=\s*([a-zA-Z0-9_\.]+)/i);
  if (joinMatch) {
    const joinTable = joinMatch[1].toLowerCase();
    const joinData = localDb[joinTable] || [];
    const leftCol = joinMatch[3].split('.').pop();
    const rightCol = joinMatch[4].split('.').pop();

    const joined = [];
    table.forEach(row => {
      const match = joinData.find(jRow => {
        return (row[leftCol] && row[leftCol] === jRow[rightCol]) || (row[rightCol] && row[rightCol] === jRow[leftCol]);
      });
      if (match) {
        const rowId = row.id;
        joined.push({ ...row, ...match, id: rowId, access_id: match.id });
      }
    });
    table = joined;
  }

  // Handle WHERE clause with parameter replacement
  const whereMatch = sql.match(/where\s+(.*?)(order\s+by|group\s+by|limit|$)/is);
  if (whereMatch) {
    const whereClause = whereMatch[1].trim();
    table = table.filter(row => evaluateWhereClause(whereClause, row, params));
  }

  // Handle ORDER BY
  const orderMatch = sql.match(/order\s+by\s+([a-zA-Z0-9_\.]+)(\s+(asc|desc))?/i);
  if (orderMatch) {
    const col = orderMatch[1].split('.').pop();
    const isDesc = (orderMatch[3] || 'asc').toLowerCase() === 'desc';
    table.sort((a, b) => {
      const valA = a[col] != null ? a[col] : '';
      const valB = b[col] != null ? b[col] : '';
      if (valA < valB) return isDesc ? 1 : -1;
      if (valA > valB) return isDesc ? -1 : 1;
      return 0;
    });
  }

  // Handle COUNT(*)
  if (lower.includes('count(')) {
    return { rows: [{ count: table.length }], rowCount: 1 };
  }

  // Handle LIMIT and OFFSET
  const limitMatch = sql.match(/limit\s+(\d+|\$\d+)/i);
  const offsetMatch = sql.match(/offset\s+(\d+|\$\d+)/i);

  let offset = 0;
  if (offsetMatch) {
    offset = offsetMatch[1].startsWith('$') 
      ? parseInt(params[parseInt(offsetMatch[1].slice(1)) - 1], 10) 
      : parseInt(offsetMatch[1], 10);
  }

  let limit = table.length;
  if (limitMatch) {
    limit = limitMatch[1].startsWith('$') 
      ? parseInt(params[parseInt(limitMatch[1].slice(1)) - 1], 10) 
      : parseInt(limitMatch[1], 10);
  }

  const paged = table.slice(offset, offset + limit);
  return { rows: paged, rowCount: paged.length };
}

function evaluateWhereClause(whereClause, row, params) {
  // Replace $1, $2 with corresponding values
  let resolved = whereClause;
  const paramMatches = [...resolved.matchAll(/\$(\d+)/g)];
  for (const m of paramMatches.reverse()) {
    const idx = parseInt(m[1], 10) - 1;
    const val = params[idx];
    const replacement = typeof val === 'string' ? `'${val.replace(/'/g, "''")}'` : (val === null ? 'NULL' : String(val));
    resolved = resolved.slice(0, m.index) + replacement + resolved.slice(m.index + m[0].length);
  }

  // Split on AND (case insensitive)
  const conditions = resolved.split(/\s+AND\s+/i);
  for (const cond of conditions) {
    const trimmed = cond.trim();

    // Check IS NOT NULL
    const isNotNullMatch = trimmed.match(/^([a-zA-Z0-9_\.]+)\s+IS\s+NOT\s+NULL$/i);
    if (isNotNullMatch) {
      const col = isNotNullMatch[1].split('.').pop();
      if (row[col] === null || row[col] === undefined) return false;
      continue;
    }

    // Check IS NULL
    const isNullMatch = trimmed.match(/^([a-zA-Z0-9_\.]+)\s+IS\s+NULL$/i);
    if (isNullMatch) {
      const col = isNullMatch[1].split('.').pop();
      if (row[col] !== null && row[col] !== undefined) return false;
      continue;
    }

    // Check ILIKE / LIKE
    const likeMatch = trimmed.match(/^([a-zA-Z0-9_\.]+)\s+I?LIKE\s+'(.*?)'$/i);
    if (likeMatch) {
      const col = likeMatch[1].split('.').pop();
      const pattern = likeMatch[2].replace(/%/g, '.*');
      const regex = new RegExp(`^${pattern}$`, 'i');
      if (!regex.test(String(row[col] || ''))) return false;
      continue;
    }

    // Check >, <, >=, <=, !=, =
    const compMatch = trimmed.match(/^([a-zA-Z0-9_\.]+)\s*(=|!=|<>|>=|<=|>|<)\s*(.*)$/);
    if (compMatch) {
      const col = compMatch[1].split('.').pop();
      const op = compMatch[2];
      let expected = compMatch[3].trim();
      if (expected.startsWith("'") && expected.endsWith("'")) {
        expected = expected.slice(1, -1);
      }
      const actual = row[col];

      if (op === '=' && String(actual) !== String(expected)) return false;
      if ((op === '!=' || op === '<>') && String(actual) === String(expected)) return false;
      if (op === '>' && !(new Date(actual) > new Date(expected) || actual > expected)) return false;
      if (op === '<' && !(new Date(actual) < new Date(expected) || actual < expected)) return false;
      if (op === '>=' && !(new Date(actual) >= new Date(expected) || actual >= expected)) return false;
      if (op === '<=' && !(new Date(actual) <= new Date(expected) || actual <= expected)) return false;
      continue;
    }
  }

  return true;
}

function executeLocalInsert(sql, params) {
  loadLocalDb();
  const match = sql.match(/insert\s+into\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*values\s*\((.*?)\)(\s*returning\s+(.*?))?$/is);
  if (!match) return { rows: [], rowCount: 0 };

  const tableName = match[1].toLowerCase();
  const columns = match[2].split(',').map(c => c.trim().toLowerCase());
  const returning = match[5] ? match[5].split(',').map(c => c.trim()) : null;

  const newRow = {
    id: uuidv4(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  columns.forEach((col, idx) => {
    newRow[col] = params[idx] !== undefined ? params[idx] : null;
  });

  if (!localDb[tableName]) {
    localDb[tableName] = [];
  }
  localDb[tableName].push(newRow);
  saveLocalDb();

  let returnObj = { ...newRow };
  if (returning && !returning.includes('*')) {
    returnObj = {};
    for (const field of returning) {
      returnObj[field] = newRow[field];
    }
  }

  return { rows: [returnObj], rowCount: 1 };
}

function executeLocalUpdate(sql, params) {
  loadLocalDb();
  const match = sql.match(/update\s+([a-zA-Z0-9_]+)\s+set\s+(.*?)\s+where\s+(.*?)(\s+returning\s+(.*?))?$/is);
  if (!match) return { rows: [], rowCount: 0 };

  const tableName = match[1].toLowerCase();
  const setPart = match[2];
  const wherePart = match[3];
  const table = localDb[tableName] || [];

  // Parse set fields
  const setAssignments = setPart.split(',').map(s => s.trim());
  const updatedRows = [];

  table.forEach(row => {
    if (evaluateWhereClause(wherePart, row, params)) {
      setAssignments.forEach(assign => {
        const [col, valRef] = assign.split('=').map(s => s.trim());
        const paramMatch = valRef.match(/\$(\d+)/);
        if (paramMatch) {
          const pIdx = parseInt(paramMatch[1], 10) - 1;
          row[col.toLowerCase()] = params[pIdx];
        } else if (valRef.toLowerCase() === 'current_timestamp' || valRef.toLowerCase() === 'now()') {
          row[col.toLowerCase()] = new Date().toISOString();
        } else if (valRef.startsWith("'") && valRef.endsWith("'")) {
          row[col.toLowerCase()] = valRef.slice(1, -1);
        } else if (!isNaN(valRef)) {
          row[col.toLowerCase()] = Number(valRef);
        }
      });
      row.updated_at = new Date().toISOString();
      updatedRows.push(row);
    }
  });

  saveLocalDb();
  return { rows: updatedRows, rowCount: updatedRows.length };
}

function executeLocalDelete(sql, params) {
  loadLocalDb();
  const match = sql.match(/delete\s+from\s+([a-zA-Z0-9_]+)\s+where\s+(.*?)$/is);
  if (!match) return { rows: [], rowCount: 0 };

  const tableName = match[1].toLowerCase();
  const wherePart = match[2];
  const initialCount = (localDb[tableName] || []).length;

  if (localDb[tableName]) {
    localDb[tableName] = localDb[tableName].filter(row => !evaluateWhereClause(wherePart, row, params));
  }
  saveLocalDb();
  const deletedCount = initialCount - (localDb[tableName] || []).length;
  return { rows: [], rowCount: deletedCount };
}

/**
 * Initializes the database connection.
 * Attempts PostgreSQL connection; if unavailable, falls back gracefully.
 */
async function initDatabase() {
  loadLocalDb();

  const pgConfig = config.databaseUrl ? { connectionString: config.databaseUrl } : config.pg;

  try {
    const testPool = new Pool({
      ...pgConfig,
      connectionTimeoutMillis: 2000,
    });

    const client = await testPool.connect();
    client.release();
    pool = testPool;
    isPostgresConnected = true;
    console.log('[Database] Connected successfully to PostgreSQL.');

    // Run schema migrations on PostgreSQL
    const schemaSql = fs.readFileSync(path.resolve(__dirname, 'schema.sql'), 'utf8');
    await pool.query(schemaSql);
    console.log('[Database] PostgreSQL schema and tables verified/created.');
  } catch (err) {
    isPostgresConnected = false;
    console.log('[Database] PostgreSQL connection not detected (' + err.message + ').');
    console.log('[Database] Running with zero-friction persistent storage at storage/database.json.');
    console.log('[Database] (To switch to PostgreSQL anytime, configure DATABASE_URL in .env and run: npm run migrate)');
  }

  return { isPostgresConnected };
}

module.exports = {
  query,
  initDatabase,
  getIsPostgresConnected: () => isPostgresConnected,
};
