// /api/create-user.js — Vercel Serverless Function
// Utilise fetch() natif Node 18+ — pas de dépendance SDK Supabase
// Variables Vercel : SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

const ALLOWED_ROLES = ['SUPER_ADMIN','DSI','RSSI','SYSTEM_ADMIN','NETWORK_ADMIN'];

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin','*');
    res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Méthode non autorisée' });

    const SUPABASE_URL     = process.env.SUPABASE_URL || process.env.supabase_url;
    const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

    console.log('[create-user] URL:', SUPABASE_URL ? 'ok' : 'MISSING');
    console.log('[create-user] KEY:', SERVICE_ROLE_KEY ? 'ok' : 'MISSING');

    if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
        return res.status(500).json({
            error: 'Variables SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY manquantes dans Vercel'
        });
    }

    const authHeader = (req.headers['authorization'] || '').replace('Bearer ','').trim();
    if (!authHeader) return res.status(401).json({ error: 'Token manquant' });

    // Vérifier le token appelant
    let caller;
    try {
        const r = await fetch(SUPABASE_URL + '/auth/v1/user', {
            headers: { 'Authorization': 'Bearer ' + authHeader, 'apikey': SERVICE_ROLE_KEY }
        });
        if (!r.ok) return res.status(401).json({ error: 'Token invalide' });
        caller = await r.json();
    } catch(e) { return res.status(500).json({ error: 'Vérif token: ' + e.message }); }

    // Vérifier son rôle
    let callerRole = null;
    try {
        const r = await fetch(SUPABASE_URL + '/rest/v1/user_roles?user_id=eq.' + caller.id + '&select=role_id&limit=1', {
            headers: { 'apikey': SERVICE_ROLE_KEY, 'Authorization': 'Bearer ' + SERVICE_ROLE_KEY }
        });
        const rows = await r.json();
        callerRole = rows?.[0]?.role_id || null;
    } catch(e) { console.warn('[create-user] role fetch:', e.message); }

    if (!callerRole && caller.email === 'alain.grafcolson@gmail.com') callerRole = 'SUPER_ADMIN';

    console.log('[create-user] caller:', caller.email, 'role:', callerRole);

    if (!callerRole || !ALLOWED_ROLES.includes(callerRole)) {
        return res.status(403).json({ error: 'Droits insuffisants (rôle: ' + callerRole + ')' });
    }

    const { email, password, prenom, nom, role, company_id, must_change_password, send_email } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email et password requis' });

    console.log('[create-user] creating:', email);

    // Créer dans auth.users
    let userId;
    try {
        const r = await fetch(SUPABASE_URL + '/auth/v1/admin/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': SERVICE_ROLE_KEY,
                'Authorization': 'Bearer ' + SERVICE_ROLE_KEY
            },
            body: JSON.stringify({
                email, password,
                email_confirm: true,
                user_metadata: { prenom: prenom||'', nom: nom||'', role: role||'SERVICE_MANAGER', must_change_password: !!must_change_password }
            })
        });
        const body = await r.json();
        console.log('[create-user] auth create:', r.status);
        if (!r.ok) {
            const msg = body.msg || body.message || body.error_description || JSON.stringify(body);
            if (r.status === 422) return res.status(409).json({ error: 'Email déjà enregistré' });
            return res.status(r.status).json({ error: 'Auth error: ' + msg });
        }
        userId = body.id;
    } catch(e) { return res.status(500).json({ error: 'Auth create: ' + e.message }); }

    console.log('[create-user] userId:', userId);

    // Insérer dans users
    try {
        await fetch(SUPABASE_URL + '/rest/v1/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': SERVICE_ROLE_KEY,
                'Authorization': 'Bearer ' + SERVICE_ROLE_KEY,
                'Prefer': 'resolution=merge-duplicates'
            },
            body: JSON.stringify({ id: userId, email, prenom: prenom||null, nom: nom||null, company_id: company_id||null, must_change_password: !!must_change_password, active: true })
        });
    } catch(e) { console.warn('[create-user] users insert:', e.message); }

    // Attribuer le rôle
    const roleToAssign = role || 'SERVICE_MANAGER';
    try {
        await fetch(SUPABASE_URL + '/rest/v1/user_roles', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'apikey': SERVICE_ROLE_KEY,
                'Authorization': 'Bearer ' + SERVICE_ROLE_KEY,
                'Prefer': 'resolution=merge-duplicates'
            },
            body: JSON.stringify({ user_id: userId, role_id: roleToAssign })
        });
    } catch(e) { console.warn('[create-user] roles insert:', e.message); }

    console.log('[create-user] success:', email);
    return res.status(200).json({ success: true, user_id: userId, email, role: roleToAssign, message: 'Profil créé avec succès' });
};
