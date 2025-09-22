const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Configuração do Pool de Conexão com PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Testar conexão com o banco
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('❌ Erro ao conectar ao banco de dados:', err.stack);
    } else {
        console.log('✅ Conexão com PostgreSQL estabelecida com sucesso.');
    }
});

// ===============================================
// SCRIPT PARA CRIAR AS TABELAS AUTOMATICAMENTE
// ===============================================
const createTablesQuery = `
-- Tabela de Usuários (ALTERADA: Foco em afiliados, não microtarefas)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    whatsapp VARCHAR(20) NOT NULL,
    password_hash TEXT NOT NULL,
    verification_token VARCHAR(6),
    balance DECIMAL(10, 2) DEFAULT 0.00,
    referrer_email VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE,
    device_id VARCHAR(255) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Dispositivos (NOVA: Track de Device ID)
CREATE TABLE IF NOT EXISTS device_links (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(255) UNIQUE NOT NULL,
    affiliate_link TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Saques (MANTIDA, mas simplificada)
CREATE TABLE IF NOT EXISTS withdrawals (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    pix_key TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'Pendente' CHECK (status IN ('Pendente', 'Pago', 'Recusado')),
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP
);
`;

// ===============================================
// SCRIPT DE MIGRAÇÃO: Adiciona coluna device_id se não existir
// ===============================================
const addDeviceIdColumnQuery = `
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='device_id') THEN
        ALTER TABLE users ADD COLUMN device_id VARCHAR(255) UNIQUE;
        RAISE NOTICE 'Coluna device_id adicionada à tabela users.';
    END IF;
END $$;
`;

// Executa os scripts em ordem
pool.query(createTablesQuery, async (err, res) => {
    if (err) {
        console.error('❌ Erro ao criar tabelas:', err.stack);
        process.exit(1);
    } else {
        console.log('✅ Tabelas criadas com sucesso (ou já existiam).');
    }

    try {
        // Executa migração para adicionar device_id
        await pool.query(addDeviceIdColumnQuery);
        console.log('✅ Migração: Coluna device_id garantida.');

        // --- CRIA O USUÁRIO ADMIN APÓS AS MIGRAÇÕES ---
        await createAdminUser();

        // --- INICIALIZA O SERVIDOR APÓS TUDO ESTAR PRONTO ---
        startServer();
    } catch (migrationError) {
        console.error('❌ Erro durante as migrações:', migrationError);
        process.exit(1);
    }
});

// ===============================================
// SCRIPT PARA CRIAR O USUÁRIO ADMINISTRADOR AUTOMATICAMENTE
// ===============================================
async function createAdminUser() {
    const adminEmail = 'admin@taskin.com';
    const adminName = 'Administrador';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Caio@2102'; // Use variável de ambiente em produção
    const adminWhatsapp = '81999999999';

    try {
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
        if (result.rows.length > 0) {
            console.log('✅ Usuário administrador já existe.');
            return;
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(adminPassword, saltRounds);

        await pool.query(
            `INSERT INTO users (name, email, whatsapp, password_hash, is_verified)
             VALUES ($1, $2, $3, $4, $5)`,
            [adminName, adminEmail, adminWhatsapp, hashedPassword, true]
        );

        console.log('✅ Usuário administrador criado com sucesso!');
    } catch (error) {
        console.error('❌ Erro ao criar usuário administrador:', error);
        throw error;
    }
}

// Função para iniciar o servidor e carregar todas as rotas
function startServer() {
    // Configuração do Nodemailer
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    // Middleware de Autenticação JWT
    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ error: 'Token inválido.' });
            req.user = user;
            next();
        });
    };

    // Middleware de Autorização de Administrador
    const authorizeAdmin = (req, res, next) => {
        if (req.user.email === 'admin@taskin.com') {
            next();
        } else {
            res.status(403).json({ error: 'Acesso negado. Área restrita a administradores.' });
        }
    };

    // Rota de Registro de Usuário (ALTERADA - Foco em Afiliados)
    app.post('/api/register', async (req, res) => {
        const { name, email, whatsapp, password, referrerEmail, device_id } = req.body;

        if (!name || !email || !whatsapp || !password) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
        }

        try {
            const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (userCheck.rows.length > 0) {
                return res.status(409).json({ error: 'E-mail já cadastrado.' });
            }

            // Verifica se o device_id já existe
            if (device_id) {
                const deviceCheck = await pool.query('SELECT id FROM users WHERE device_id = $1', [device_id]);
                if (deviceCheck.rows.length > 0) {
                    return res.status(409).json({ error: 'Já existe uma conta cadastrada neste aparelho.' });
                }
            }

            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();

            const result = await pool.query(
                'INSERT INTO users (name, email, whatsapp, password_hash, verification_token, referrer_email, device_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, email, whatsapp',
                [name, email, whatsapp, hashedPassword, verificationToken, referrerEmail || null, device_id || null]
            );

            const newUser = result.rows[0];

            console.log(`[DEV] Código de verificação para ${email}: ${verificationToken}`);
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Verifique seu e-mail - Taskin',
                html: `<p>Seu código de verificação é: <strong>${verificationToken}</strong></p>`,
            });

            res.status(201).json({
                message: 'Usuário registrado com sucesso. Verifique seu e-mail.',
                user: { id: newUser.id, name: newUser.name, email: newUser.email, whatsapp: newUser.whatsapp }
            });
        } catch (error) {
            console.error('Erro no registro:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // Rota de Login (ALTERADA - Verifica is_verified)
    app.post('/api/login', async (req, res) => {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
        }

        try {
            const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

            if (result.rows.length === 0) {
                return res.status(400).json({ error: 'Credenciais inválidas.' });
            }

            const user = result.rows[0];

            // Verifica se o e-mail foi verificado
            if (!user.is_verified) {
                return res.status(403).json({ error: 'E-mail não verificado. Por favor, confirme seu e-mail antes de fazer login.' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password_hash);

            if (!isPasswordValid) {
                return res.status(400).json({ error: 'Credenciais inválidas.' });
            }

            const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });

            res.json({
                message: 'Login realizado com sucesso.',
                token: token,
                user: { id: user.id, name: user.name, email: user.email, whatsapp: user.whatsapp, balance: user.balance }
            });
        } catch (error) {
            console.error('Erro no login:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // --- ROTA DE TRACKING DE DEVICE ID (NOVA) ---
    app.post('/api/track-device', async (req, res) => {
        const { device_id } = req.body;

        if (!device_id) {
            return res.status(400).json({ error: 'ID do dispositivo é obrigatório.' });
        }

        try {
            // Salva ou atualiza o device_id no banco
            await pool.query(
                `INSERT INTO device_links (device_id, affiliate_link) 
                 VALUES ($1, $2) 
                 ON CONFLICT (device_id) 
                 DO UPDATE SET affiliate_link = $2`,
                [device_id, 'https://peer2profit.com/?ref=SEUCODIGO']
            );

            res.json({ message: 'Device ID trackeado com sucesso.' });
        } catch (error) {
            console.error('Erro ao trackear device ID:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });
    // --- FIM DA ROTA DE TRACKING ---

    // --- ROTA DE DOWNLOAD SEGURO (NOVA) ---
    app.get('/api/download', (req, res) => {
        // Redireciona SEMPRE pro seu link de afiliado
        res.redirect('https://peer2profit.com/?ref=SEUCODIGO');
    });
    // --- FIM DA ROTA DE DOWNLOAD ---

    // --- ROTA DE DOWNLOAD DINÂMICO POR DEVICE ID (AVANÇADA) ---
    app.get('/api/secure-download', async (req, res) => {
        const userAgent = req.get('User-Agent');
        const ip = req.ip;
        const deviceId = crypto.createHash('md5').update(userAgent + ip).digest('hex');

        try {
            // Salva no banco
            await pool.query(
                `INSERT INTO device_links (device_id, affiliate_link, created_at) 
                 VALUES ($1, $2, NOW()) 
                 ON CONFLICT (device_id) 
                 DO NOTHING`,
                [deviceId, 'https://peer2profit.com/?ref=SEUCODIGO']
            );

            // Redireciona SEMPRE pro seu link
            res.redirect('https://peer2profit.com/?ref=SEUCODIGO');
        } catch (error) {
            console.error('Erro ao gerar link seguro:', error);
            res.redirect('https://peer2profit.com/?ref=SEUCODIGO');
        }
    });
    // --- FIM DA ROTA DINÂMICA ---

    // Rota para obter histórico de saques do usuário
    app.get('/api/withdrawals/history', authenticateToken, async (req, res) => {
        const userId = req.user.id;

        try {
            const result = await pool.query(
                `SELECT id, amount, pix_key, status, requested_at, processed_at
                 FROM withdrawals 
                 WHERE user_id = $1
                 ORDER BY requested_at DESC`,
                [userId]
            );

            res.json(result.rows);
        } catch (error) {
            console.error('Erro ao buscar histórico de saques:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // Rota para solicitar saque
    app.post('/api/withdrawals', authenticateToken, async (req, res) => {
        const { amount, pixKey } = req.body;
        const userId = req.user.id;

        if (!amount || !pixKey) {
            return res.status(400).json({ error: 'Valor e chave PIX são obrigatórios.' });
        }

        if (amount < 10) {
            return res.status(400).json({ error: 'Valor mínimo para saque é R$10,00.' });
        }

        try {
            // Verifica saldo
            const user = await pool.query('SELECT balance FROM users WHERE id = $1', [userId]);
            if (user.rows[0].balance < amount) {
                return res.status(400).json({ error: 'Saldo insuficiente.' });
            }

            // Insere solicitação de saque
            const result = await pool.query(
                'INSERT INTO withdrawals (user_id, amount, pix_key, status) VALUES ($1, $2, $3, $4) RETURNING *',
                [userId, amount, pixKey, 'Pendente']
            );

            res.status(201).json({
                message: 'Saque solicitado com sucesso. Aguarde aprovação.',
                withdrawal: result.rows[0]
            });
        } catch (error) {
            console.error('Erro ao solicitar saque:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // ========================
    // ROTAS DO PAINEL ADMIN
    // ========================

    // Obter todos os usuários (Admin)
    app.get('/api/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
        try {
            const result = await pool.query(
                'SELECT id, name, email, whatsapp, balance, created_at FROM users ORDER BY created_at DESC'
            );
            res.json(result.rows);
        } catch (error) {
            console.error('Erro ao buscar usuários:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // Obter saques pendentes (Admin)
    app.get('/api/admin/withdrawals/pending', authenticateToken, authorizeAdmin, async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT w.id, w.amount, w.pix_key, w.requested_at, w.status, u.name as user_name, u.email as user_email
                 FROM withdrawals w
                 JOIN users u ON w.user_id = u.id
                 WHERE w.status = 'Pendente'
                 ORDER BY w.requested_at DESC`
            );
            res.json(result.rows);
        } catch (error) {
            console.error('Erro ao buscar saques pendentes:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // Processar saque (Admin)
    app.put('/api/admin/withdrawals/:id/process', authenticateToken, authorizeAdmin, async (req, res) => {
        const { id } = req.params;
        const { status } = req.body;

        if (!['Pago', 'Recusado'].includes(status)) {
            return res.status(400).json({ error: 'Status inválido. Use "Pago" ou "Recusado".' });
        }

        try {
            const result = await pool.query(
                'UPDATE withdrawals SET status = $1, processed_at = NOW() WHERE id = $2 RETURNING *',
                [status, id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Saque não encontrado.' });
            }

            // Se pago, deduz do saldo do usuário
            if (status === 'Pago') {
                const withdrawal = result.rows[0];
                await pool.query(
                    'UPDATE users SET balance = balance - $1 WHERE id = $2',
                    [withdrawal.amount, withdrawal.user_id]
                );
            }

            res.json({ message: `Saque ${status.toLowerCase()} com sucesso.`, withdrawal: result.rows[0] });
        } catch (error) {
            console.error('Erro ao processar saque:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });

    // --- ROTA DE VERIFICAÇÃO DE DEVICE ID (PARA FRONTEND) ---
    app.post('/api/check-device', async (req, res) => {
        const { device_id } = req.body;

        if (!device_id) {
            return res.status(400).json({ error: 'ID do dispositivo é obrigatório.' });
        }

        try {
            const result = await pool.query('SELECT id FROM users WHERE device_id = $1', [device_id]);
            res.json({ exists: result.rows.length > 0 });
        } catch (error) {
            console.error('Erro ao verificar device ID:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });
    // --- FIM DA ROTA DE VERIFICAÇÃO ---

    // --- ROTA DE VERIFICAÇÃO DE E-MAIL ---
    app.post('/api/verify-email', async (req, res) => {
        const { email, token } = req.body;

        if (!email || !token) {
            return res.status(400).json({ error: 'E-mail e token são obrigatórios.' });
        }

        try {
            const result = await pool.query(
                'SELECT id, verification_token, created_at FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado.' });
            }

            const user = result.rows[0];

            if (user.verification_token !== token) {
                return res.status(400).json({ error: 'Token inválido.' });
            }

            const tokenAge = new Date() - new Date(user.created_at);
            const oneHourInMs = 60 * 60 * 1000;
            if (tokenAge > oneHourInMs) {
                return res.status(400).json({ error: 'Token expirado. Solicite um novo.' });
            }

            await pool.query('UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE id = $1', [user.id]);

            res.json({ message: 'E-mail verificado com sucesso! Você já pode fazer login.' });
        } catch (error) {
            console.error('Erro na verificação de e-mail:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });
    // --- FIM DA ROTA DE VERIFICAÇÃO ---

    // --- ROTA DE REENVIO DE TOKEN ---
    app.post('/api/resend-token', async (req, res) => {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'E-mail é obrigatório.' });
        }

        try {
            const result = await pool.query(
                'SELECT id, is_verified FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado.' });
            }

            const user = result.rows[0];

            if (user.is_verified) {
                return res.status(400).json({ error: 'Este e-mail já foi verificado.' });
            }

            const newToken = Math.floor(100000 + Math.random() * 900000).toString();

            await pool.query(
                'UPDATE users SET verification_token = $1, created_at = NOW() WHERE id = $2',
                [newToken, user.id]
            );

            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Novo código de verificação - Taskin',
                html: `<p>Seu novo código de verificação é: <strong>${newToken}</strong></p>`,
            });

            console.log(`[DEV] Novo código de verificação para ${email}: ${newToken}`);
            res.json({ message: 'Novo código enviado com sucesso! Verifique sua caixa de entrada.' });
        } catch (error) {
            console.error('Erro ao reenviar token:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });
    // --- FIM DA ROTA DE REENVIO ---

    // Servir arquivos estáticos (seu frontend)
    app.use(express.static(__dirname));

    // Rota catch-all para SPA (se estiver usando frontend em React/Vue)
    app.get('*', (req, res) => {
        res.sendFile(__dirname + '/index.html');
    });

    // Inicia o servidor
    app.listen(PORT, () => {
        console.log(`🚀 Servidor Taskin rodando em http://localhost:${PORT}`);
        console.log(`🌐 Site do Usuário: http://localhost:${PORT}`);
        console.log(`🛠️  Painel Admin: http://localhost:${PORT}/admin.html`);
    });
}

module.exports = app;