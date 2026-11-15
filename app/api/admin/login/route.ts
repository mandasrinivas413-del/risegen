import type { RowDataPacket } from 'mysql2/promise'
import { getDb } from '@/lib/db'
import {
  clearAuthFailures,
  createAdminSession,
  getAdminEmail,
  hashPassword,
  isAuthRateLimited,
  isSameOrigin,
  readJsonBody,
  recordAuthFailure,
  sessionCookie,
  verifyPassword,
} from '@/lib/admin-auth'

export const runtime = 'nodejs'

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return Response.json({ error: 'Invalid request origin.' }, { status: 403 })
  const body = await readJsonBody(request)
  if (!body || typeof body.email !== 'string' || typeof body.password !== 'string') {
    return Response.json({ error: 'Enter your email and password.' }, { status: 400 })
  }
  if (body.password.length > 128) return Response.json({ error: 'Invalid email or password.' }, { status: 401 })
  if (await isAuthRateLimited(request, 'login')) {
    return Response.json({ error: 'Too many attempts. Try again in 15 minutes.' }, { status: 429 })
  }

  const email = body.email.trim().toLowerCase()
  const adminEmail = getAdminEmail()
  const [rows] = await getDb().execute<RowDataPacket[]>(`
    SELECT email, password_salt, password_hash, session_version, must_change_password
    FROM admin_users
    WHERE email = ?
    LIMIT 1
  `, [adminEmail])
  let admin = rows[0]

  if (!admin && email === adminEmail && process.env.ADMIN_INITIAL_PASSWORD &&
      body.password === process.env.ADMIN_INITIAL_PASSWORD) {
    const { salt, hash } = await hashPassword(body.password)
    await getDb().execute(`
      INSERT INTO admin_users (email, password_salt, password_hash, must_change_password)
      VALUES (?, ?, ?, TRUE)
      ON DUPLICATE KEY UPDATE email = admin_users.email
    `, [adminEmail, salt, hash])
    const [updatedRows] = await getDb().execute<RowDataPacket[]>(`
      SELECT email, password_salt, password_hash, session_version, must_change_password
      FROM admin_users
      WHERE email = ?
      LIMIT 1
    `, [adminEmail])
    admin = updatedRows[0]
  }

  const valid = email === adminEmail && admin &&
    await verifyPassword(body.password, String(admin.password_salt), String(admin.password_hash))
  if (!valid) {
    await recordAuthFailure(request, 'login')
    return Response.json({ error: 'Invalid email or password.' }, { status: 401 })
  }

  await clearAuthFailures(request, 'login')
  const response = Response.json({ saved: true, mustChangePassword: Boolean(admin.must_change_password) })
  response.headers.append('Set-Cookie', sessionCookie(createAdminSession(adminEmail, Number(admin.session_version))))
  return response
}
