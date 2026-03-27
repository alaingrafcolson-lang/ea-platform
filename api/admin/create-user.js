import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

const supabaseAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Fonction de hashage simple (SHA-256) pour les réponses aux questions
async function hashAnswer(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export default async function handler(req, res) {
  // Autoriser uniquement les requêtes POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  try {
    // 1. Vérifier que l'utilisateur est authentifié et est Super Admin
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non authentifié' });
    }

    const token = authHeader.split(' ')[1];
    const { data: { user }, error: userError } = await supabaseAnon.auth.getUser(token);
    
    if (userError || !user) {
      return res.status(401).json({ error: 'Token invalide' });
    }

    // Vérifier le rôle Super Admin
    const isSuperAdmin = user.user_metadata?.role === 'super_admin';
    if (!isSuperAdmin) {
      return res.status(403).json({ error: 'Permission refusée. Seul un Super Admin peut créer des utilisateurs.' });
    }

    // 2. Récupérer les données du formulaire
    const { email, password, userType, securityAnswers } = req.body;
    
    if (!email || !password || !userType) {
      return res.status(400).json({ error: 'Email, mot de passe et type requis' });
    }

    if (!securityAnswers || !Array.isArray(securityAnswers) || securityAnswers.length !== 2) {
      return res.status(400).json({ error: 'Deux questions de sécurité sont requises' });
    }

    // 3. Créer l'utilisateur dans Supabase Auth
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

    // 4. Hasher et insérer les réponses aux questions de sécurité
    const answersToInsert = [];
    for (const answer of securityAnswers) {
      const hashed = await hashAnswer(answer.answer);
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

    // 5. Ajouter l'utilisateur dans la table ea_users
    let roleMapping = 'DATA';
    if (userType === 'RSSI') roleMapping = 'RSSI';
    else if (userType === 'DSI') roleMapping = 'DSI';
    else if (userType === 'SERVICE_MANAGER') roleMapping = 'SERVICE_MANAGER';
    else if (userType === 'CEO') roleMapping = 'CEO';
    else if (userType === 'NET') roleMapping = 'NET';
    else if (userType === 'SYS') roleMapping = 'SYS';
    
    await supabaseAdmin
      .from('ea_users')
      .insert({
        email: email,
        nom: email.split('@')[0],
        role: roleMapping
      });

    // 6. Retourner le succès
    return res.status(200).json({ 
      message: 'Utilisateur créé avec succès', 
      userId: authUser.user.id 
    });
    
  } catch (err) {
    console.error('Erreur serveur:', err);
    return res.status(500).json({ error: 'Erreur interne du serveur' });
  }
}
