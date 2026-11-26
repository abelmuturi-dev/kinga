/** Optional Ollama adapter, fixed to loopback. It can rephrase but never authoritatively fix. */
export async function rephraseWithLocalModel(
  advice: { summary: string; why: string; steps: string[]; verify: string },
  model: string,
  options: { fetcher?: typeof fetch; timeoutMs?: number } = {},
): Promise<string> {
  if (!/^[A-Za-z0-9._:-]{1,100}$/.test(model)) throw new Error('Invalid local model name.');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 20_000);
  try {
    const response = await (options.fetcher ?? fetch)('http://127.0.0.1:11434/api/generate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        stream: false,
        prompt: [
          'Rewrite this curated security advice in clear simple language.',
          'Do not add facts, vulnerabilities, code, commands or remediation steps.',
          'Preserve every technical requirement. If unsure, repeat the original wording.',
          JSON.stringify(advice),
        ].join('\n\n'),
      }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Local model request failed with HTTP ${response.status}.`);
    const payload: unknown = await response.json();
    if (
      typeof payload !== 'object' ||
      payload === null ||
      typeof (payload as { response?: unknown }).response !== 'string'
    ) {
      throw new Error('Local model returned an invalid response.');
    }
    return (payload as { response: string }).response.trim();
  } finally {
    clearTimeout(timeout);
  }
}
