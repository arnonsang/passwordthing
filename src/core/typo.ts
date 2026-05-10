export interface TypoResult {
  match: boolean;
  distance: number;
  message: 'Match' | '1 character off' | 'Significantly different';
}

export function checkTypo(a: string, b: string): TypoResult {
  const distance = levenshtein(a, b);
  const match = distance === 0;
  const message: TypoResult['message'] =
    distance === 0 ? 'Match' : distance === 1 ? '1 character off' : 'Significantly different';
  return { match, distance, message };
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const m = a.length;
  const n = b.length;

  let prev: number[] = Array.from({ length: n + 1 }, (_, i) => i);
  let curr: number[] = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }

  return prev[n]!;
}
