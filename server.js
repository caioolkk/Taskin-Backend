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
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

// Testar conexão com o banco
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('❌ Erro ao conectar ao banco de dados:', err.stack);
    } else {
        console.log('✅ Conexão com PostgreSQL estabelecida com sucesso.');
    }
});

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

// Rota de Registro de Usuário
app.post('/api/register', async (req, res) => {
    const { name, email, whatsapp, password } = req.body;

    if (!name || !email || !whatsapp || !password) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }

    try {
        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) {
            return res.status(409).json({ error: 'E-mail já cadastrado.' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();

        const result = await pool.query(
            'INSERT INTO users (name, email, whatsapp, password_hash, verification_token) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, whatsapp',
            [name, email, whatsapp, hashedPassword, verificationToken]
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

// Rota de Login
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

// Rota fallback para SPA
app.get('*', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor Taskin rodando em http://localhost:${PORT}`);
    console.log(`🌐 Site do Usuário: http://localhost:${PORT}`);
    console.log(`🛠️  Painel Admin: http://localhost:${PORT}/admin.html`);
});