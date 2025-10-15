import axios from 'axios';

const users = [
  { nome: 'João Silva',    cpf:'12345678011', email: 'joao@test.com',   senha: 'senha123' },
  { nome: 'Maria Oliveira',cpf:'98765432022', email: 'maria@test.com',  senha: 'senha123' },
  { nome: 'Carlos Souza',  cpf:'65432198033', email: 'carlos@test.com', senha: 'senha123' },
  { nome: 'Ana Costa',     cpf:'11223344556', email: 'ana@test.com',    senha: 'senha123' },
  { nome: 'Pedro Almeida', cpf:'55664433221', email: 'pedro@test.com',  senha: 'senha123' },
];

async function seed() {
  for (const u of users) {
    try {
      const { data } = await axios.post('http://localhost:3000/api/usuarios', u);
      console.log('✅', data);
    } catch (e) {
      console.error('❌', e.response?.data || e.message);
    }
  }
}

seed();
