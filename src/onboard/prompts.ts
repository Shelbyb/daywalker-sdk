import readline from "node:readline/promises";

export interface Prompter {
  ask(question: string, fallback?: string): Promise<string>;
  hidden(question: string): Promise<string>;
  confirm(question: string, fallback?: boolean): Promise<boolean>;
  close(): void;
}

/** Interactive prompter built on node:readline. `hidden` mutes echo so passwords never appear. */
export function createPrompter(): Prompter {
  let muted = false;
  const output = {
    write(chunk: string) {
      if (!muted) process.stdout.write(chunk);
      return true;
    },
    on() {},
    once() {},
    emit() {},
    removeListener() {},
  };
  const rl = readline.createInterface({ input: process.stdin, output: output as any, terminal: Boolean(process.stdin.isTTY) });
  return {
    async ask(question, fallback = "") {
      const answer = (await rl.question(fallback ? `${question} [${fallback}]: ` : `${question}: `)).trim();
      return answer || fallback;
    },
    async hidden(question) {
      process.stdout.write(`${question}: `);
      muted = true;
      try {
        return await rl.question("");
      } finally {
        muted = false;
        process.stdout.write("\n");
      }
    },
    async confirm(question, fallback = false) {
      const answer = (await rl.question(`${question} [${fallback ? "Y/n" : "y/N"}]: `)).trim().toLowerCase();
      return answer ? answer.startsWith("y") : fallback;
    },
    close: () => rl.close(),
  };
}
