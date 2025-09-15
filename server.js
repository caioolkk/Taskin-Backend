const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');

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
-- Tabela de Usuários (ALTERADA: Adicionadas colunas is_verified, device_id e referrer_email)
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

-- Tabela de Tarefas
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    details TEXT NOT NULL,
    link TEXT NOT NULL,
    network VARCHAR(100) NOT NULL,
    value DECIMAL(10, 2) NOT NULL,
    max_completions INTEGER NOT NULL,
    current_completions INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'completed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Relacionamento Usuário-Tarefas
CREATE TABLE IF NOT EXISTS user_tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'submitted', 'approved', 'rejected')),
    proof_link TEXT,
    submitted_at TIMESTAMP,
    approved_at TIMESTAMP,
    rejected_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Saques
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

// Executa o script de criação de tabelas
pool.query(createTablesQuery, (err, res) => {
    if (err) {
        console.error('❌ Erro ao criar tabelas:', err.stack);
    } else {
        console.log('✅ Tabelas criadas com sucesso (ou já existiam).');
        // --- CHAMA A CRIAÇÃO DO ADMIN APÓS AS TABELAS ESTAREM PRONTAS ---
        createAdminUser();
    }
});

// ===============================================
// SCRIPT PARA CRIAR O USUÁRIO ADMINISTRADOR AUTOMATICAMENTE
// ===============================================
async function createAdminUser() {
    const adminEmail = 'admin@taskin.com';
    const adminName = 'Administrador';
    const adminPassword = 'Caio@2102'; // <-- ALTERE AQUI SE QUISER UMA SENHA DIFERENTE
    const adminWhatsapp = '81999999999';

    try {
        // Verifica se o admin já existe
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
        if (result.rows.length > 0) {
            console.log('✅ Usuário administrador já existe.');
            return;
        }

        // Gera o hash da senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(adminPassword, saltRounds);

        // Insere o usuário admin
        await pool.query(
            `INSERT INTO users (name, email, whatsapp, password_hash, is_verified)
             VALUES ($1, $2, $3, $4, $5)`,
            [adminName, adminEmail, adminWhatsapp, hashedPassword, true]
        );

        console.log('✅ Usuário administrador criado com sucesso!');
    } catch (error) {
        console.error('❌ Erro ao criar usuário administrador:', error);
    }
}
// --- REMOVA A CHAMADA AUTOMÁTICA DAQUI ---
// createAdminUser(); // <-- ESTA LINHA FOI REMOVIDA
// ===============================================
// FIM DO SCRIPT DE CRIAÇÃO DO ADMIN
// ===============================================

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

// Rota de Registro de Usuário (ALTERADA - Versão Final com Device ID)
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

// --- INÍCIO DA NOVA ROTA: Verificar Device ID ---
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
// --- FIM DA NOVA ROTA ---

// --- INÍCIO DA NOVA ROTA: Verificar E-mail ---
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

        // Verifica se o token corresponde
        if (user.verification_token !== token) {
            return res.status(400).json({ error: 'Token inválido.' });
        }

        // Verifica se o token expirou (1 hora)
        const tokenAge = new Date() - new Date(user.created_at);
        const oneHourInMs = 60 * 60 * 1000;
        if (tokenAge > oneHourInMs) {
            return res.status(400).json({ error: 'Token expirado. Solicite um novo.' });
        }

        // Atualiza o status do usuário para verificado
        await pool.query('UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE id = $1', [user.id]);

        res.json({ message: 'E-mail verificado com sucesso! Você já pode fazer login.' });
    } catch (error) {
        console.error('Erro na verificação de e-mail:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});
// --- FIM DA NOVA ROTA ---

// --- INÍCIO DA NOVA ROTA: Reenviar Token de Verificação ---
app.post('/api/resend-token', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'E-mail é obrigatório.' });
    }

    try {
        // Verifica se o usuário existe
        const result = await pool.query(
            'SELECT id, is_verified FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        const user = result.rows[0];

        // Verifica se o e-mail já foi verificado
        if (user.is_verified) {
            return res.status(400).json({ error: 'Este e-mail já foi verificado.' });
        }

        // Gera um novo token
        const newToken = Math.floor(100000 + Math.random() * 900000).toString();

        // Atualiza o token no banco de dados
        await pool.query(
            'UPDATE users SET verification_token = $1, created_at = NOW() WHERE id = $2',
            [newToken, user.id]
        );

        // Envia o novo token por e-mail
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
// --- FIM DA NOVA ROTA ---

// Rota para obter a PRÓXIMA tarefa disponível (UMA POR VEZ)
app.get('/api/tasks/next', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        // Verifica se o usuário já tem uma tarefa pendente ou em análise
        const pendingTask = await pool.query(
            'SELECT ut.id, ut.status, t.* FROM user_tasks ut JOIN tasks t ON ut.task_id = t.id WHERE ut.user_id = $1 AND ut.status IN ($2, $3)',
            [userId, 'pending', 'submitted']
        );

        if (pendingTask.rows.length > 0) {
            return res.json({ task: pendingTask.rows[0] });
        }

        // Se não tem tarefa pendente, busca a próxima disponível
        const availableTask = await pool.query(
            `SELECT * FROM tasks 
             WHERE status = 'active' 
             AND current_completions < max_completions 
             AND id NOT IN (
                 SELECT task_id FROM user_tasks WHERE user_id = $1 AND status = 'approved'
             )
             ORDER BY id ASC LIMIT 1`,
            [userId]
        );

        if (availableTask.rows.length === 0) {
            return res.json({ task: null, message: 'Nenhuma tarefa disponível no momento.' });
        }

        const task = availableTask.rows[0];

        // Atribui a tarefa ao usuário
        await pool.query(
            'INSERT INTO user_tasks (user_id, task_id, status) VALUES ($1, $2, $3)',
            [userId, task.id, 'pending']
        );

        res.json({ task: task });
    } catch (error) {
        console.error('Erro ao buscar próxima tarefa:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Rota para enviar comprovante
app.post('/api/tasks/submit-proof', authenticateToken, async (req, res) => {
    const { taskId, proofLink } = req.body;
    const userId = req.user.id;

    if (!taskId || !proofLink) {
        return res.status(400).json({ error: 'ID da tarefa e link do comprovante são obrigatórios.' });
    }

    try {
        // Verifica se a tarefa pertence ao usuário e está pendente
        const userTask = await pool.query(
            'SELECT * FROM user_tasks WHERE id = $1 AND user_id = $2 AND status = $3',
            [taskId, userId, 'pending']
        );

        if (userTask.rows.length === 0) {
            return res.status(400).json({ error: 'Tarefa não encontrada ou já processada.' });
        }

        // Atualiza para "submitted"
        await pool.query(
            'UPDATE user_tasks SET status = $1, proof_link = $2, submitted_at = NOW() WHERE id = $3',
            ['submitted', proofLink, taskId]
        );

        res.json({ message: 'Comprovante enviado com sucesso. Aguarde aprovação.' });
    } catch (error) {
        console.error('Erro ao enviar comprovante:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// --- INÍCIO DA ROTA ALTERADA: Notificar Indicador ---
// Rota para notificar o indicador que o indicado completou uma tarefa
app.post('/api/tasks/notify-referrer', authenticateToken, async (req, res) => {
    const { taskId } = req.body;
    const userId = req.user.id;

    if (!taskId) {
        return res.status(400).json({ error: 'ID da tarefa é obrigatório.' });
    }

    try {
        // Verifica se a tarefa foi aprovada
        const userTask = await pool.query(
            'SELECT * FROM user_tasks WHERE id = $1 AND user_id = $2 AND status = $3',
            [taskId, userId, 'approved']
        );

        if (userTask.rows.length === 0) {
            return res.status(400).json({ error: 'Tarefa não encontrada ou não aprovada.' });
        }

        // Busca o e-mail do indicador e verifica se o usuário indicado está em conformidade
        const user = await pool.query('SELECT referrer_email, is_verified, device_id FROM users WHERE id = $1', [userId]);

        if (!user.rows[0].is_verified) {
            return res.status(403).json({ error: 'O usuário indicado precisa ter o e-mail verificado para liberar o bônus.' });
        }

        if (!user.rows[0].device_id) {
            return res.status(403).json({ error: 'O usuário indicado precisa ter um device_id válido para liberar o bônus.' });
        }

        if (!user.rows[0].referrer_email) {
            return res.status(200).json({ message: 'Nenhum indicador encontrado.' });
        }

        const referrerEmail = user.rows[0].referrer_email;

        // Busca o ID do usuário indicador
        const referrer = await pool.query('SELECT id FROM users WHERE email = $1', [referrerEmail]);

        if (referrer.rows.length === 0) {
            return res.status(404).json({ error: 'Usuário indicador não encontrado.' });
        }

        const referrerId = referrer.rows[0].id;

        // Atualiza o saldo do indicador
        await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [1.00, referrerId]
        );

        res.json({ message: 'Indicador notificado e bônus de R$1,00 creditado com sucesso.' });
    } catch (error) {
        console.error('Erro ao notificar indicador:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});
// --- FIM DA ROTA ALTERADA ---

// Rota para obter histórico de tarefas do usuário
app.get('/api/tasks/history', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const result = await pool.query(
            `SELECT ut.id, ut.status, ut.submitted_at, ut.approved_at, ut.rejected_at, 
                    t.title, t.value, t.network
             FROM user_tasks ut
             JOIN tasks t ON ut.task_id = t.id
             WHERE ut.user_id = $1
             ORDER BY ut.created_at DESC`,
            [userId]
        );

        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar histórico:', error);
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

// Obter TODAS as tarefas ativas (para o painel admin)
app.get('/api/admin/tasks/active', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, title, summary, network, value, current_completions, max_completions, status FROM tasks WHERE status = $1 ORDER BY id DESC',
            ['active']
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar tarefas ativas:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Obter tarefas pendentes de aprovação
app.get('/api/admin/tasks/pending', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT ut.id as user_task_id, ut.proof_link, ut.submitted_at,
                    u.name as user_name, u.email as user_email, u.whatsapp,
                    t.title, t.value, t.network
             FROM user_tasks ut
             JOIN users u ON ut.user_id = u.id
             JOIN tasks t ON ut.task_id = t.id
             WHERE ut.status = 'submitted'
             ORDER BY ut.submitted_at ASC`
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar tarefas pendentes:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Aprovar tarefa
app.put('/api/admin/tasks/:id/approve', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        // Busca detalhes da tarefa
        const userTask = await pool.query(
            `SELECT ut.user_id, t.value, t.id as task_id
             FROM user_tasks ut
             JOIN tasks t ON ut.task_id = t.id
             WHERE ut.id = $1 AND ut.status = 'submitted'`,
            [id]
        );

        if (userTask.rows.length === 0) {
            return res.status(404).json({ error: 'Tarefa não encontrada ou já processada.' });
        }

        const { user_id, value, task_id } = userTask.rows[0];

        // Atualiza status da tarefa do usuário
        await pool.query(
            'UPDATE user_tasks SET status = $1, approved_at = NOW() WHERE id = $2',
            ['approved', id]
        );

        // Atualiza contagem da tarefa
        await pool.query(
            'UPDATE tasks SET current_completions = current_completions + 1 WHERE id = $1',
            [task_id]
        );

        // Atualiza saldo do usuário
        await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [value, user_id]
        );

        // Chama a rota internamente para creditar o bônus ao indicador
        try {
            const notifyResponse = await fetch(`${process.env.BASE_URL || 'http://localhost:3000'}/api/tasks/notify-referrer`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': req.headers['authorization']
                },
                body: JSON.stringify({ taskId: id })
            });
            const notifyData = await notifyResponse.json();
            if (!notifyResponse.ok) {
                console.warn('Erro ao notificar indicador:', notifyData.error);
            } else {
                console.log(notifyData.message);
            }
        } catch (notifyError) {
            console.warn('Erro ao chamar rota de notificação:', notifyError.message);
        }

        res.json({ message: 'Tarefa aprovada e saldo creditado com sucesso.' });
    } catch (error) {
        console.error('Erro ao aprovar tarefa:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Recusar tarefa
app.put('/api/admin/tasks/:id/reject', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.query(
            'UPDATE user_tasks SET status = $1, rejected_at = NOW() WHERE id = $2 AND status = $3',
            ['rejected', id, 'submitted']
        );

        res.json({ message: 'Tarefa recusada com sucesso.' });
    } catch (error) {
        console.error('Erro ao recusar tarefa:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Adicionar nova tarefa (Admin)
app.post('/api/admin/tasks', authenticateToken, authorizeAdmin, async (req, res) => {
    const { title, summary, details, link, network, value, max_completions } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO tasks (title, summary, details, link, network, value, max_completions, status) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'active') RETURNING *`,
            [title, summary, details, link, network, value, max_completions]
        );

        res.status(201).json({ message: 'Tarefa adicionada com sucesso.', task: result.rows[0] });
    } catch (error) {
        console.error('Erro ao adicionar tarefa:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Obter todos os usuários (Admin)
app.get('/api/admin/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, email, whatsapp, balance, created_at FROM users ORDER BY created_at DESC');
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

        res.json({ message: `Saque ${status.toLowerCase()} com sucesso.`, withdrawal: result.rows[0] });
    } catch (error) {
        console.error('Erro ao processar saque:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// Servir arquivos estáticos
app.use(express.static(__dirname));

app.listen(PORT, () => {
    console.log(`🚀 Servidor Taskin rodando em http://localhost:${PORT}`);
    console.log(`🌐 Site do Usuário: http://localhost:${PORT}`);
    console.log(`🛠️  Painel Admin: http://localhost:${PORT}/admin.html`);
});