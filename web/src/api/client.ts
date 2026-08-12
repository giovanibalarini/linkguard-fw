import axios from 'axios';

const client = axios.create({
  baseURL: '',
  timeout: 15000,
});

// Timeout para as ações que podem instalar pacote antes de fazer o que
// prometeram: o apply de DHCP/DNS (kea + unbound + dns-root-data) e a
// instalação do chrony.
//
// O timeout padrão de 15s não serve para elas. Pior: quando ele estourava, o
// apt NÃO morria junto (a unidade transiente do systemd-run termina a
// instalação), então o admin via um erro enquanto a instalação terminava com
// sucesso. O backend já foi desamarrado do cliente (applyBudget, em
// internal/api/handlers/netsvc.go); aqui o front espera o resultado de
// verdade em vez de inventar uma falha.
//
// A tela mostra, enquanto isso, que uma instalação pode estar em curso —
// ninguém deve encarar um botão desabilitado por minutos sem explicação.
export const INSTALL_TIMEOUT_MS = 15 * 60 * 1000;

// isTimeout distingue "desisti de esperar" de "o servidor respondeu erro".
// A diferença importa: no primeiro caso o trabalho provavelmente continua.
export const isTimeout = (e: any) => e?.code === 'ECONNABORTED' || e?.code === 'ETIMEDOUT';

// Attach JWT token from localStorage to every request
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    const scheme = 'Bearer';
    config.headers.Authorization = `${scheme} ${token}`;
  }
  return config;
});

// Redirect to login on 401
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default client;
