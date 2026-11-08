// Artificial horizon. Shows N/A overlay when attitude is unavailable or stale.
export default function Attitude({ roll, pitch, yaw, stale }: { roll: number | null; pitch: number | null; yaw: number | null; stale?: boolean }) {
  const has = roll !== null && pitch !== null;
  const r = roll ?? 0;
  const p = Math.max(-40, Math.min(40, pitch ?? 0));
  return (
    <svg viewBox="-100 -100 200 200" className="horizon" role="img" aria-label="attitude indicator">
      <defs>
        <clipPath id="hz-clip"><circle r="92" /></clipPath>
      </defs>
      <g clipPath="url(#hz-clip)">
        <g transform={`rotate(${-r}) translate(0 ${p * 2})`}>
          <rect x="-300" y="-300" width="600" height="300" fill="#1c4c73" />
          <rect x="-300" y="0" width="600" height="300" fill="#5a3d22" />
          <line x1="-300" x2="300" y1="0" y2="0" stroke="#e8eef3" strokeWidth="1.5" />
          {[-30, -20, -10, 10, 20, 30].map((d) => (
            <g key={d}>
              <line x1={-(Math.abs(d) % 20 === 0 ? 26 : 14)} x2={Math.abs(d) % 20 === 0 ? 26 : 14} y1={-d * 2} y2={-d * 2} stroke="#e8eef3" strokeWidth="1" opacity="0.8" />
              {Math.abs(d) % 20 === 0 && <text x="32" y={-d * 2 + 3} fontSize="8" fill="#e8eef3">{Math.abs(d)}</text>}
            </g>
          ))}
        </g>
      </g>
      <circle r="92" fill="none" stroke="var(--line-2)" strokeWidth="3" />
      <path d="M-44 0 L-14 0 L-8 7 M44 0 L14 0 L8 7" stroke="#ffcc33" strokeWidth="3" fill="none" />
      <circle r="2.5" fill="#ffcc33" />
      <g transform={`rotate(${-r})`}><path d="M0 -92 L-5 -82 L5 -82 Z" fill="#ffcc33" /></g>
      <text x="0" y="86" textAnchor="middle" fontSize="10" fill="#e8eef3" fontFamily="var(--mono)">
        {yaw === null ? "HDG N/A" : `HDG ${((yaw + 360) % 360).toFixed(0)}°`}
      </text>
      {(!has || stale) && (
        <g>
          <rect x="-60" y="-14" width="120" height="28" rx="4" fill="rgba(11,15,20,0.85)" />
          <text x="0" y="5" textAnchor="middle" fontSize="11" fill={stale ? "#f2b84b" : "#9fb0bf"} fontWeight="700">{stale ? "ATTITUDE STALE" : "ATTITUDE N/A"}</text>
        </g>
      )}
    </svg>
  );
}
