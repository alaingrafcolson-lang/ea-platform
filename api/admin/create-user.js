import { createClient } from '@supabase/supabase-js'

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
)

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const token = req.headers.authorization?.replace('Bearer ', '')

  const { data: { user }, error } =
    await supabaseAdmin.auth.getUser(token)

  if (error || !user) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  // Vérification rôle
  const { data: role } = await supabaseAdmin
    .from('user_roles')
    .select('role_id')
    .eq('user_id', user.id)
    .single()

  if (!role || !['SUPER_ADMIN','DSI'].includes(role.role_id)) {
    return res.status(403).json({ error: 'Forbidden' })
  }

  const { email, prenom, nom, role_id, company_id } = req.body

  // Création user
  const { data: newUser, error: createError } =
    await supabaseAdmin.auth.admin.createUser({
      email,
      email_confirm: true
    })

  if (createError) {
    return res.status(400).json({ error: createError.message })
  }

  const userId = newUser.user.id

  await supabaseAdmin.from('users').insert({
    id: userId,
    email,
    prenom,
    nom,
    company_id,
    active: true
  })

  await supabaseAdmin.from('user_roles').insert({
    user_id: userId,
    role_id
  })

  return res.status(200).json({ success: true })
}
