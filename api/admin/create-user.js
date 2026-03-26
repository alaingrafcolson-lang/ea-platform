import { createClient } from '@supabase/supabase-js';

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  try {
    const { email, password, userType, securityAnswers } = req.body;
    
    if (!email || !password || !userType) {
      return res.status(400).json({ error: 'Email, mot de passe et type requis' });
    }

    // Créer l'utilisateur
    const { data: authUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { type: userType, role: 'user' }
    });

    if (createError) {
      return res.status(400).json({ error: createError.message });
    }

    // Ajouter dans ea_users
    await supabaseAdmin
      .from('ea_users')
      .insert({
        email: email,
        nom: email.split('@')[0],
        role: userType
      });

    return res.status(200).json({ 
      message: 'Utilisateur créé avec succès', 
      userId: authUser.user.id 
    });
    
  } catch (err) {
    console.error('Erreur:', err);
    return res.status(500).json({ error: 'Erreur interne du serveur' });
  }
}
