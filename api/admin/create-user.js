import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcrypt';

const supabaseAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Vérification du token et du rôle Super Admin
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Non authentifié' });
  }

  const token = authHeader.split(' ')[1];
  const { data: { user }, error: userError } = await supabaseAnon.auth.getUser(token);
  if (userError || !user) {
    return res.status(401).json({ error: 'Token invalide' });
  }

  const isSuperAdmin = user.user_metadata?.role === 'super_admin';
  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'Permission refusée' });
  }

  // Récupération des données
  const { email, password, userType, securityAnswers } = req.body;
  if (!email || !password || !userType || !securityAnswers || !Array.isArray(securityAnswers)) {
    return res.status(400).json({ error: 'Champs manquants' });
  }

  // Création de l'utilisateur dans Auth
  const { data: authUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { type: userType, role: 'user' }
  });

  if (createError) {
    console.error('Erreur création user:', createError);
    return res.status(400).json({ error: createError.message });
  }

  // Hashage et insertion des réponses
  const answersToInsert = [];
  for (const answer of securityAnswers) {
    const hashed = await bcrypt.hash(answer.answer, 10);
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
    await supabaseAdmin.auth.admin.deleteUser(authUser.user.id);
    return res.status(500).json({ error: 'Erreur sauvegarde des réponses' });
  }

  res.status(200).json({ message: 'Utilisateur créé avec succès', userId: authUser.user.id });
}
