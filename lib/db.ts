import mysql, { type Pool } from 'mysql2/promise'

const globalForMysql = globalThis as typeof globalThis & { mysqlPool?: Pool }

export function getDb(): Pool {
  const host = process.env.DB_HOST
  const database = process.env.DB_NAME
  const user = process.env.DB_USER
  const password = process.env.DB_PASSWORD
  const port = Number(process.env.DB_PORT || '3306')

  if (!host || !database || !user || !password) {
    throw new Error('DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD must be configured')
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('DB_PORT must be a valid TCP port')
  }

  if (!globalForMysql.mysqlPool) {
    globalForMysql.mysqlPool = mysql.createPool({
      host,
      database,
      user,
      password,
      port,
      waitForConnections: true,
      connectionLimit: 5,
      maxIdle: 2,
      idleTimeout: 60_000,
      queueLimit: 0,
      charset: 'utf8mb4',
      timezone: 'Z',
      supportBigNumbers: true,
      bigNumberStrings: true,
    })
  }

  return globalForMysql.mysqlPool
}
