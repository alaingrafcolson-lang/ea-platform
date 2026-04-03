const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Seulement POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  // ---- Vérification des variables d'environnement ----
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // Logs pour debug (visibles dans Vercel)
  console.log('SUPABASE_URL présent ?', !!SUPABASE_URL);
  console.log('SERVICE_ROLE_KEY présent ?', !!SERVICE_ROLE_KEY);

  if (!SUPABASE_URL) {
    console.error('SUPABASE_URL manquante');
    return res.status(500).json({ error: 'SUPABASE_URL non définie' });
  }
  if (!SERVICE_ROLE_KEY) {
    console.error('SUPABASE_SERVICE_ROLE_KEY manquante');
    return res.status(500).json({ error: 'SUPABASE_SERVICE_ROLE_KEY non définie' });
  }

  // ---- Initialisation du client admin ----
  const sb = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // ---- Vérification du token de l'appelant ----
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant ou mal formé' });
  }
  const token = authHeader.split(' ')[1];

  const { data: { user: caller }, error: authError } = await sb.auth.getUser(token);
  if (authError || !caller) {
    console.error('Erreur auth:', authError?.message);
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }

  // ---- Vérification des droits (rôle) ----
  const { data: roleData, error: roleError } = await sb
    .from('user_roles')
    .select('role_id')
    .eq('user_id', caller.id)
    .maybeSingle();

  if (roleError) {
    console.error('Erreur lecture rôle:', roleError.message);
    return res.status(500).json({ error: 'Erreur lors de la vérification des droits' });
  }

  const allowedRoles = ['SUPER_ADMIN', 'DSI', 'RSSI', 'SYSTEM_ADMIN', 'NETWORK_ADMIN'];
  if (!roleData || !allowedRoles.includes(roleData.role_id)) {
    return res.status(403).json({ error: 'Droits insuffisants' });
  }

  // ---- Paramètres du nouvel utilisateur ----
  const { email, password, prenom, nom, role, company_id, must_change_password, send_email } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  // ---- Création de l'utilisateur ----
  const { data: newUser, error: createError } = await sb.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { prenom, nom, role, must_change_password: !!must_change_password }
  });

  if (createError) {
    console.error('Erreur createUser:', createError.message);
    if (createError.message.includes('already registered')) {
      return res.status(409).json({ error: 'Cet email existe déjà' });
    }
    return res.status(400). json({ error: createError.message });
  }

  const userId = newUser.user.id;

  // ---- Insertion dans la table users ----
  const { error: insertUserError } = await sb.from('users').upsert({
    id: userId,
    email,
    prenom: prenom || null,
    nom: nom || null,
    company_id: company_id || null,
    must_change_password: !!must_change_password,
    active: true
  }, { onConflict: 'id' });

  if (insertUserError) {
    console.error('Erreur insert users:', insertUserError.message);
    // On continue, l'essentiel est fait
  }

  // ---- Attribution du rôle ----
  const roleToAssign = role || 'SERVICE_MANAGER';
  const { error: roleInsertError } = await sb.from('user_roles').upsert({
    user_id: userId,
    role_id: roleToAssign
  }, { onConflict: 'user_id' });

  if (roleInsertError) {
    console.error('Erreur insert role:', roleInsertError.message);
  }

  // ---- Envoi d'email si demandé ----
  if (send_email) {
    try {
      await sb.auth.admin.generateLink({
        type: 'recovery',
        email,
        options: { redirectTo: 'https://ea-platform-omega.vercel.app/index.html' }
      });
    } catch (emailError) {
      console.error('Erreur envoi email:', emailError.message);
    }
  }

  // ---- Succès ----
  return res.status(200).json({
    success: true,
    user_id: userId,
    email,
    role: roleToAssign,
    message: 'Profil créé avec succès'
  });
};
