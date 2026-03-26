import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  // Autoriser uniquement les requêtes GET
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  try {
    const { data, error } = await supabase
      .from('security_questions')
      .select('id, question_text')
      .order('id');

    if (error) {
      console.error('Erreur Supabase:', error);
      return res.status(500).json({ error: error.message });
    }

    // Retourner la liste des questions
    res.status(200).json(data);
  } catch (err) {
    console.error('Erreur serveur:', err);
    res.status(500).json({ error: 'Erreur interne du serveur' });
  }
}
