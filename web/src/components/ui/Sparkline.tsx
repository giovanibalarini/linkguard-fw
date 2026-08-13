import { LineChart, Line, ResponsiveContainer } from 'recharts';

export interface SparklinePoint {
  ts: number;
  /** bits/s; `null` é intervalo sem amostra, e não se desenha. */
  rx: number | null;
  /** bits/s; `null` é intervalo sem amostra, e não se desenha. */
  tx: number | null;
}

interface SparklineProps {
  data: SparklinePoint[];
  height?: number;
}

export default function Sparkline({ data, height = 32 }: SparklineProps) {
  if (data.length < 2) {
    return (
      <div style={{ height }} className="flex items-center text-gray-600 text-xs">
        sem dados
      </div>
    );
  }
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 2, bottom: 2, left: 0, right: 0 }}>
          <Line type="linear" dataKey="rx" stroke="#22d3ee" strokeWidth={1.5} dot={false} isAnimationActive={false} />
          <Line type="linear" dataKey="tx" stroke="#34d399" strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
