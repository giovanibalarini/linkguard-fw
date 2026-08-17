/**
 * errMsg tira do erro do axios a mensagem que o BACKEND escreveu, e só cai no
 * genérico quando não há nenhuma.
 *
 * Isso importa mais aqui do que parece: é o backend que sabe dizer "não foi
 * possível concluir a reversão; o LinkGuard vai tentar de novo sozinho" ou por
 * que o `nft -c` recusou a regra. Trocar essa frase por "erro interno do
 * servidor" tira do operador justamente o que ele precisa para agir.
 */
export function errMsg(e: unknown): string {
  const ax = e as { response?: { data?: { error?: string } }; message?: string };
  return ax?.response?.data?.error || ax?.message || 'falha na operação';
}
