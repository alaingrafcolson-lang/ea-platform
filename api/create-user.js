const { createClient } = require('@supabase/supabase-js');

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Méthode non autorisée' });

  // 1. Récupérer les variables d'environnement
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    console.error('Variables manquantes:', { SUPABASE_URL: !!SUPABASE_URL, SERVICE_ROLE_KEY: !!SERVICE_ROLE_KEY });
    return res.status(500).json({ error: 'Configuration serveur incomplète' });
  }

  // 2. Client admin (service_role)
  const sb = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // 3. Vérifier le token de l'appelant (utilisateur déjà connecté)
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  const { data: { user: caller }, error: authErr } = await sb.auth.getUser(token);
  if (authErr || !caller) return res.status(401).json({ error: 'Session invalide' });

  // 4. Vérifier les droits (rôle autorisé)
  const { data: roleRow } = await sb
    .from('user_roles')
    .select('role_id')
    .eq('user_id', caller.id)
    .maybeSingle();

  const allowedRoles = ['SUPER_ADMIN', 'DSI', 'RSSI', 'SYSTEM_ADMIN', 'NETWORK_ADMIN'];
  if (!roleRow || !allowedRoles.includes(roleRow.role_id)) {
    return res.status(403).json({ error: 'Droits insuffisants' });
  }

  // 5. Paramètres du nouvel utilisateur
  const { email, password, prenom, nom, role, company_id, must_change_password, send_email } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

  // 6. Création dans auth.users
  const { data: newUser, error: createErr } = await sb.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { prenom, nom, role, must_change_password: !!must_change_password }
  });

  if (createErr) {
    if (createErr.message.includes('already registered')) {
      return res.status(409).json({ error: 'Cet email est déjà utilisé' });
    }
    console.error('Erreur createUser:', createErr);
    return res.status(400).json({ error: createErr.message });
  }

  const userId = newUser.user.id;

  // 7. Insertion dans la table `users`
  const { error: insertUserErr } = await sb.from('users').upsert({
    id: userId,
    email,
    prenom: prenom || null,
    nom: nom || null,
    company_id: company_id || null,
    must_change_password: !!must_change_password,
    active: true
  }, { onConflict: 'id' });

  if (insertUserErr) console.error('Erreur insert users:', insertUserErr);

  // 8. Attribution du rôle
  const roleToAssign = role || 'SERVICE_MANAGER';
  const { error: roleInsertErr } = await sb.from('user_roles').upsert({
    user_id: userId,
    role_id: roleToAssign
  }, { onConflict: 'user_id' });

  if (roleInsertErr) console.error('Erreur insert user_roles:', roleInsertErr);

  // 9. Envoi d'email si demandé
  if (send_email) {
    await sb.auth.admin.generateLink({
      type: 'recovery',
      email,
      options: { redirectTo: 'https://ea-platform-omega.vercel.app/index.html' }
    });
  }

  return res.status(200).json({
    success: true,
    user_id: userId,
    email,
    role: roleToAssign,
    message: 'Profil créé avec succès'
  });
};
