const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const SECRET_KEY = process.env.JWT_SECRET || "chave-temporaria-local";

// LOGIN - OK
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ erro: "E-mail ou senha incorretos" });

        const user = result.rows[0];
        const senhaBate = await bcrypt.compare(password, user.password_hash);

        if (senhaBate) {
            const token = jwt.sign(
                { institution_id: user.institution_id }, 
                SECRET_KEY, 
                { expiresIn: '24h' }
            );
            // IMPORTANTE: Retornar o institution_id aqui
            res.json({ 
                mensagem: "Logado!", 
                token: token, 
                institution_id: user.institution_id 
            });
        } else {
            res.status(401).json({ erro: "E-mail ou senha incorretos" });
        }
    } catch (error) {
        res.status(500).json({ erro: "Erro no servidor" });
    }
});

// LISTAR AGENDAMENTOS (PROTEGIDO) - OK
app.get('/agendamentos/meus', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ erro: "Sem token!" });

    try {
        const dados = jwt.verify(token, SECRET_KEY);
        const result = await pool.query(
            'SELECT * FROM appointments WHERE institution_id = $1 ORDER BY data, horario',
            [dados.institution_id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(401).json({ erro: "Token inválido" });
    }
});

// ROTA PARA CONSULTAR HORÁRIOS OCUPADOS (PÚBLICA)
app.get('/agendamentos/ocupados', async (req, res) => {
    const { data, instId } = req.query;
    try {
        const result = await pool.query(
            'SELECT horario FROM appointments WHERE data = $1 AND institution_id = $2',
            [data, instId]
        );
        res.json(result.rows.map(row => row.horario));
    } catch (err) {
        res.status(500).json([]);
    }
});

// CRIAR AGENDAMENTO (PÚBLICO PARA CLIENTES)
app.post('/agendamentos/:institution_id', async (req, res) => {
    const { institution_id } = req.params;
    const { nome, email, data, horario } = req.body;

  try {
    // 1. Validar se a data não é passada
    const dataAgendamento = new Date(data + 'T00:00:00');
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);

    if (dataAgendamento < hoje) {
      return res.status(400).json({ erro: 'Data inválida.' });
    }

    // 2. Verificar se já existe agendamento
    const check = await pool.query(
      'SELECT id FROM appointments WHERE data = $1 AND horario = $2 AND institution_id = $3',
      [data, horario, institution_id]
    );

    if (check.rows.length > 0) {
      return res.status(400).json({ erro: 'Este horário acabou de ser ocupado.' });
    }

    // 3. Inserir
    await pool.query(
      `INSERT INTO appointments (nome, email, data, horario, institution_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [nome, email, data, horario, institution_id]
    );
    res.status(201).json({ mensagem: 'Agendamento realizado!' });
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno ao agendar.' });
  }
});

// ROTA PARA CONSULTAR HORÁRIOS OCUPADOS (PÚBLICA)
app.get('/agendamentos/ocupados', async (req, res) => {
    const { data, instId } = req.query;
    try {
        const result = await pool.query(
            'SELECT horario FROM appointments WHERE data = $1 AND institution_id = $2',
            [data, instId]
        );
        res.json(result.rows.map(row => row.horario));
    } catch (err) {
        res.status(500).json([]);
    }
});

// CRIAR AGENDAMENTO (PRIVADO PARA DONOS)
app.post('/agendamentos/users', async (req, res) => {
  const token = req.headers['authorization'];

  try {
    const dados = jwt.verify(token, SECRET_KEY); // pega do token
    const institution_id = dados.institution_id;

    const { nome, email, data, horario } = req.body;

    // validação simples
    if (!nome || !email || !data || !horario) {
      return res.status(400).json({ erro: 'Dados incompletos' });
    }

    const dataAgendamento = new Date(data + 'T00:00:00');
    const hoje = new Date();
    hoje.setHours(0,0,0,0);

    if (dataAgendamento < hoje) {
      return res.status(400).json({ erro: 'Data inválida.' });
    }

    const check = await pool.query(
      'SELECT id FROM appointments WHERE data = $1 AND horario = $2 AND institution_id = $3',
      [data, horario, institution_id]
    );

    if (check.rows.length > 0) {
      return res.status(400).json({ erro: 'Horário ocupado' });
    }

    await pool.query(
      `INSERT INTO appointments (nome, email, data, horario, institution_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [nome, email, data, horario, institution_id]
    );

    res.status(201).json({ mensagem: 'Agendado!' });

  } catch (error) {
    return res.status(401).json({ erro: 'Não autorizado' });
  }
});

// EDITAR (PROTEGIDO) - OK
app.put('/agendamentos/:id', async (req, res) => {
    const { id } = req.params;
    const { data, horario } = req.body;
    const token = req.headers['authorization'];

    try {
        jwt.verify(token, SECRET_KEY);

        // --- TRAVA DE DATA NA EDIÇÃO ---
        const dataEdicao = new Date(data + 'T00:00:00');
        const hoje = new Date();
        hoje.setHours(0, 0, 0, 0);

        if (dataEdicao < hoje) {
            return res.status(400).json({ erro: 'Não é possível mover um agendamento para o passado.' });
        }
        // -------------------------------

        await pool.query(
            'UPDATE appointments SET data = $1, horario = $2 WHERE id = $3',
            [data, horario, id]
        );
        res.json({ mensagem: "Atualizado com sucesso" });
    } catch (error) {
        res.status(401).json({ erro: "Não autorizado ou data inválida" });
    }
});

// DELETE (AGORA PROTEGIDO!)
app.delete('/agendamentos/:id', async (req, res) => {
    const { id } = req.params;
    const token = req.headers['authorization'];

    try {
        // Agora só deleta se estiver logado!
        jwt.verify(token, SECRET_KEY);
        
        await pool.query('DELETE FROM appointments WHERE id = $1', [id]);
        res.json({ mensagem: 'Agendamento deletado'});
    } catch (error){
        res.status(401).json({ erro: 'Não autorizado para deletar'});
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🔥 Backend rodando na porta ${port}`);
});