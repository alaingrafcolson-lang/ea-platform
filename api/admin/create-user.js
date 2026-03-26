import { createClient } from '@supabase/supabase-js';

// Client standard (clé anon)
const supabaseAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Client admin (clé service_role) – nécessaire pour créer des utilisateurs
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// Fonction de hashage SHA-256 (alternative à bcrypt, sans dépendance externe)
async function hashAnswer(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(req, res) {
  // Autoriser uniquement les requêtes POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  // 1. Vérifier que l'utilisateur est authentifié
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Non authentifié' });
  }

  const token = authHeader.split(' ')[1];
  const { data: { user }, error: userError } = await supabaseAnon.auth.getUser(token);
  
  if (userError || !user) {
    return res.status(401).json({ error: 'Token invalide' });
  }

  // 2. Vérifier que l'utilisateur est Super Admin
  const isSuperAdmin = user.user_metadata?.role === 'super_admin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'Permission refusée. Seul un Super Admin peut créer des utilisateurs.' });
  }

  // 3. Récupérer les données du formulaire
  const { email, password, userType, securityAnswers } = req.body;
  
  if (!email || !password || !userType || !securityAnswers || !Array.isArray(securityAnswers)) {
    return res.status(400).json({ error: 'Tous les champs sont requis' });
  }

  // 4. Créer l'utilisateur dans Supabase Auth
  const { data: authUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { 
      type: userType, 
      role: 'user',
      full_name: email.split('@')[0]
    }
  });

  if (createError) {
    console.error('Erreur création utilisateur:', createError);
    return res.status(400).json({ error: createError.message });
  }

  // 5. Hasher et insérer les réponses aux questions de sécurité
  const answersToInsert = [];
  for (const answer of securityAnswers) {
    const hashed = await hashAnswer(answer.answer.toLowerCase().trim());
    answersToInsert.push({
      user_id: authUser.user.id,
      question_id: answer.questionId,
      answer_hash: hashed
    });
  }

  const { error: insertError } = await supabaseAdmin
    .from('user_security_answers')
    .insert(answersToInsert);

  if (insertError) {
    console.error('Erreur insertion réponses:', insertError);
    // Rollback : supprimer l'utilisateur créé
    await supabaseAdmin.auth.admin.deleteUser(authUser.user.id);
    return res.status(500).json({ error: 'Erreur lors de la sauvegarde des réponses' });
  }

  // 6. Optionnel : ajouter l'utilisateur dans la table ea_users
  try {
    await supabaseAdmin
      .from('ea_users')
      .insert({
        email: email,
        nom: email.split('@')[0],
        role: userType === 'RSSI' ? 'RSSI' : (userType === 'DSI' ? 'DSI' : 'DATA')
      });
  } catch (err) {
    console.warn('Erreur ajout dans ea_users (non bloquante):', err.message);
  }

  // 7. Retourner le succès
  res.status(200).json({ 
    message: 'Utilisateur créé avec succès', 
    userId: authUser.user.id 
  });
}
