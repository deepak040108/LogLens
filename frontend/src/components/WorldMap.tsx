import { useMemo } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import landTopology from "../assets/land-110m.json";
import { COUNTRY_CENTROIDS } from "../lib/countryCentroids";
import type { CountryRow } from "../types";

const WIDTH = 760;
const HEIGHT = 360;

interface Props {
  byCountry: CountryRow[];
  selectedCountry: string | null;
  onSelectCountry: (code: string | null) => void;
}

export default function WorldMap({ byCountry, selectedCountry, onSelectCountry }: Props) {
  const { landPath, markers } = useMemo(() => {
    const projection = geoNaturalEarth1().fitSize([WIDTH, HEIGHT], { type: "Sphere" } as never);
    const pathGen = geoPath(projection as never);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const land = feature(landTopology as any, (landTopology as any).objects.land);

    const maxCount = Math.max(1, ...byCountry.map((c) => c.attackCount));
    const pts = byCountry
      .map((c) => {
        const centroid = c.countryCode ? COUNTRY_CENTROIDS[c.countryCode] : null;
        if (!centroid) return null;
        const projected = projection(centroid as never);
        if (!projected) return null;
        const [x, y] = projected;
        const r = 6 + (c.attackCount / maxCount) * 16;
        return { ...c, x, y, r };
      })
      .filter((p): p is NonNullable<typeof p> => p !== null);

    return { landPath: pathGen(land as never), markers: pts };
  }, [byCountry]);

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} width="100%" height="auto" role="img" aria-label="World map of attacker locations">
      <rect x="0" y="0" width={WIDTH} height={HEIGHT} fill="#0d1016" rx="4" />
      <path d={landPath ?? undefined} fill="#1a1f28" stroke="#232a35" strokeWidth="0.5" />
      {markers.map((m) => {
        const isSelected = selectedCountry === m.countryCode;
        return (
          <g
            key={m.countryCode}
            onClick={() => onSelectCountry(isSelected ? null : m.countryCode)}
            className="cursor-pointer"
          >
            <circle cx={m.x} cy={m.y} r={m.r} fill="#ef4444" fillOpacity={isSelected ? 0.35 : 0.16} />
            <circle
              cx={m.x}
              cy={m.y}
              r={Math.max(3.5, m.r * 0.35)}
              fill="#ef4444"
              stroke={isSelected ? "#3b82f6" : "#0d1016"}
              strokeWidth={isSelected ? 2 : 1}
            />
            <text x={m.x} y={m.y - m.r - 5} textAnchor="middle" fontSize="10.5" fontFamily="IBM Plex Mono, monospace" fill="#8b93a1">
              {m.countryCode} · {m.attackCount}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
