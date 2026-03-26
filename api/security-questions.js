export default async function handler(req, res) {
  // Réponse directe sans appel à Supabase
  const questions = [
    { id: 1, question_text: "Quel est le nom de votre premier animal de compagnie ?" },
    { id: 2, question_text: "Quelle est votre ville de naissance ?" },
    { id: 3, question_text: "Quel est le modèle de votre première voiture ?" },
    { id: 4, question_text: "Quel est le nom de votre meilleur ami d'enfance ?" },
    { id: 5, question_text: "Quelle est votre couleur préférée ?" }
  ];
  
  return res.status(200).json(questions);
}
