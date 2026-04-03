const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Méthode non autorisée' });

  // ---- ÉTAPE 1 : Lire et valider les variables d'environnement ----
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // Pour le diagnostic : on renvoie un message clair si manquantes
  if (!SUPABASE_URL) {
    console.error('SUPABASE_URL manquante dans process.env');
    return res.status(500).json({ 
      error: 'Configuration serveur incomplète', 
      missing: 'SUPABASE_URL',
      hint: 'Ajoutez SUPABASE_URL dans les variables d\'environnement Vercel'
    });
  }
  if (!SERVICE_ROLE_KEY) {
    console.error('SUPABASE_SERVICE_ROLE_KEY manquante dans process.env');
    return res.status(500).json({ 
      error: 'Configuration serveur incomplète', 
      missing: 'SUPABASE_SERVICE_ROLE_KEY',
      hint: 'Ajoutez la clé secret (sb_secret_...) dans Vercel'
    });
  }

  // ---- ÉTAPE 2 : Initialiser le client Supabase (admin) ----
  const sbAdmin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // ---- ÉTAPE 3 : Vérifier le token JWT de l'appelant ----
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) {
    return res.status(401).json({ error: 'Token d\'authentification manquant' });
  }

  const { data: { user: caller }, error: authErr } = await sbAdmin.auth.getUser(token);
  if (authErr || !caller) {
    console.error('Auth error:', authErr?.message);
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }

  // ---- ÉTAPE 4 : Vérifier les droits (rôle autorisé) ----
  const { data: roleRow, error: roleError } = await sbAdmin
    .from('user_roles')
    .select('role_id')
    .eq('user_id', caller.id)
    .maybeSingle();

  if (roleError) {
    console.error('Erreur lecture user_roles:', roleError.message);
    return res.status(500).json({ error: 'Erreur interne de vérification des droits' });
  }

  const allowedRoles = ['SUPER_ADMIN', 'DSI', 'RSSI', 'SYSTEM_ADMIN', 'NETWORK_ADMIN'];
  if (!roleRow || !allowedRoles.includes(roleRow.role_id)) {
    return res.status(403).json({ error: 'Droits insuffisants pour créer un utilisateur' });
  }

  // ---- ÉTAPE 5 : Récupérer les paramètres du nouvel utilisateur ----
  const { email, password, prenom, nom, role, company_id, must_change_password, send_email } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis' });
  }

  // ---- ÉTAPE 6 : Créer l'utilisateur dans auth.users (service_role) ----
  const { data: newUser, error: createErr } = await sbAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { prenom, nom, role, must_change_password: !!must_change_password }
  });

  if (createErr) {
    console.error('Erreur createUser:', createErr.message);
    if (createErr.message.includes('already registered')) {
      return res.status(409).json({ error: 'Cet email est déjà utilisé' });
    }
    return res.status(400).json({ error: createErr.message });
  }

  const userId = newUser.user.id;

  // ---- ÉTAPE 7 : Insérer dans la table `users` ----
  const { error: insertUserErr } = await sbAdmin.from('users').upsert({
    id: userId,
    email,
    prenom: prenom || null,
    nom: nom || null,
    company_id: company_id || null,
    must_change_password: !!must_change_password,
    active: true
  }, { onConflict: 'id' });

  if (insertUserErr) console.error('Erreur insert users:', insertUserErr.message);

  // ---- ÉTAPE 8 : Attribuer le rôle ----
  const roleToAssign = role || 'SERVICE_MANAGER';
  const { error: roleInsertErr } = await sbAdmin.from('user_roles').upsert({
    user_id: userId,
    role_id: roleToAssign
  }, { onConflict: 'user_id' });

  if (roleInsertErr) console.error('Erreur insert user_roles:', roleInsertErr.message);

  // ---- ÉTAPE 9 : Envoyer un email de réinitialisation si demandé ----
  if (send_email) {
    try {
      await sbAdmin.auth.admin.generateLink({
        type: 'recovery',
        email,
        options: { redirectTo: 'https://ea-platform-omega.vercel.app/index.html' }
      });
    } catch (emailErr) {
      console.error('Erreur envoi email:', emailErr.message);
      // On ne bloque pas la création pour une erreur d'email
    }
  }

  // ---- SUCCÈS ----
  return res.status(200).json({
    success: true,
    user_id: userId,
    email,
    role: roleToAssign,
    message: 'Profil créé avec succès'
  });
};
