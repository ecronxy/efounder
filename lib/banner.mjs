// Start-up banner: "eFounder" in ANSI Shadow letters with a TON-blue gradient.
const ART = [
  ' ██████╗ ███████╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗ ',
  '██╔═══██╗██╔════╝██╔═══██╗██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗',
  '████████║█████╗  ██║   ██║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝',
  '██╔═════╝██╔══╝  ██║   ██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗',
  '╚███████╗██║     ╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║',
  ' ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝',
];
const AUTHOR = 'by ecronx.t.me';

// left to right: TON blue -> light cyan
const FROM = [0, 152, 234];
const TO = [140, 225, 255];

function useColor(stream) {
  return stream.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
}

export function banner(stream = process.stdout) {
  const width = ART[0].length;
  const color = useColor(stream);
  // the art needs 71 columns; narrower terminals get a one-liner instead of a wrapped mess
  if (stream.columns && stream.columns < width + 2) {
    return `\n  ${color ? '\x1b[1;38;2;0;152;234m' : ''}eFounder${color ? '\x1b[0m\x1b[2m' : ''}  ${AUTHOR}${color ? '\x1b[0m' : ''}\n`;
  }
  const lines = ART.map((row) => {
    if (!color) return '  ' + row;
    let out = '  ';
    for (let i = 0; i < row.length; i++) {
      const t = i / (width - 1);
      const [r, g, b] = FROM.map((c, k) => Math.round(c + (TO[k] - c) * t));
      out += `\x1b[38;2;${r};${g};${b}m${row[i]}`;
    }
    return out + '\x1b[0m';
  });
  const author = ' '.repeat(2 + width - AUTHOR.length) + AUTHOR;
  lines.push(color ? `\x1b[2m${author}\x1b[0m` : author);
  return '\n' + lines.join('\n') + '\n';
}
