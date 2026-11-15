import type { RowDataPacket } from 'mysql2/promise'
import { getDb } from '@/lib/db'
import { readSessionCookie, verifyAdminSession } from '@/lib/admin-auth'

export const runtime = 'nodejs'
const pageSize = 10

export async function GET(request: Request) {
  const session = await verifyAdminSession(readSessionCookie(request.headers.get('cookie')))
  if (!session) return Response.json({ error: 'Please log in to view enquiries.' }, { status: 401 })
  if (session.mustChangePassword) {
    return Response.json({ error: 'Change your temporary password to continue.' }, { status: 403 })
  }

  const requestedPage = Number(new URL(request.url).searchParams.get('page') ?? '1')
  if (!Number.isSafeInteger(requestedPage) || requestedPage < 1) {
    return Response.json({ error: 'Invalid page number.' }, { status: 400 })
  }

  const [countRows] = await getDb().execute<RowDataPacket[]>('SELECT COUNT(*) AS total FROM enquiries')
  const total = Number(countRows[0]?.total ?? 0)
  const pageCount = Math.ceil(total / pageSize)
  const page = Math.min(requestedPage, Math.max(pageCount, 1))
  const offset = (page - 1) * pageSize
  const [enquiries] = await getDb().execute<RowDataPacket[]>(`
    SELECT CAST(id AS CHAR) AS id, name, subject, phone, course, mode, message, path,
           created_at
    FROM enquiries
    ORDER BY created_at DESC
    LIMIT ?
    OFFSET ?
  `, [pageSize, offset])
  return Response.json(
    { enquiries, page, pageSize, total, pageCount },
    { headers: { 'Cache-Control': 'private, no-store' } },
  )
}
