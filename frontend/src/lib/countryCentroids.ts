// Approximate (lon, lat) centroids for map plotting only -- not used
// for any actual geolocation, just to place a marker for a country
// code that real GeoIP (or its absence) already determined. Covers a
// broad set of common ISO 3166-1 alpha-2 codes; a code not in this
// table simply won't get a marker (it still counts correctly in the
// by-country table, it just isn't plotted).
export const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  US: [-97, 38], CA: [-106, 56], MX: [-102, 23], BR: [-53, -10], AR: [-64, -34],
  GB: [-2, 54], FR: [2.2, 46.6], DE: [10, 51], ES: [-3.7, 40.4], IT: [12.5, 42.5],
  NL: [5.3, 52.1], BE: [4.5, 50.5], CH: [8.2, 46.8], AT: [14.5, 47.5], SE: [15, 62],
  NO: [8.5, 60.5], FI: [26, 64], DK: [10, 56], PL: [19.1, 51.9], PT: [-8, 39.5],
  IE: [-8, 53.4], GR: [22, 39], RU: [90, 61], UA: [31.2, 48.4], TR: [35, 39],
  CN: [104, 35], JP: [138, 36], KR: [127.8, 36.3], IN: [79, 22], VN: [106, 16],
  TH: [101, 15], ID: [113.9, -0.8], PH: [122, 13], MY: [101.9, 4.2], SG: [103.8, 1.35],
  PK: [69.3, 30], BD: [90.4, 23.7], AU: [134, -25], NZ: [174, -41],
  ZA: [24, -29], NG: [8, 9.1], EG: [30, 26.8], KE: [37.9, -0.02], MA: [-6, 32],
  SA: [45, 24], AE: [54, 24], IL: [34.8, 31.5], IR: [53, 32], IQ: [43.7, 33],
  CO: [-74, 4], PE: [-76, -9.2], CL: [-71, -35], VE: [-66, 8], EC: [-78.2, -1.8],
  RO: [24.9, 45.9], BG: [25.5, 42.7], HU: [19.5, 47.2], CZ: [15.5, 49.8], SK: [19.7, 48.7],
  RS: [21, 44], HR: [15.2, 45.1], VN2: [106, 16],
};
