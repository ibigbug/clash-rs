import { useEffect, useRef } from 'react';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';

interface TrafficChartProps {
  timestamps: number[];
  up: number[];
  down: number[];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB/s`;
}

function makeGradient(u: uPlot, color: string, alpha: string): CanvasGradient {
  const gradient = u.ctx.createLinearGradient(0, 0, 0, u.height);
  gradient.addColorStop(0, color + alpha);
  gradient.addColorStop(1, color + '00');
  return gradient;
}

export function TrafficChart({ timestamps, up, down }: TrafficChartProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<uPlot | null>(null);
  const dataRef = useRef({ timestamps, up, down });

  // Keep dataRef current so resize observer always uses latest data.
  dataRef.current = { timestamps, up, down };

  function buildChart(width: number) {
    if (!containerRef.current) return;
    chartRef.current?.destroy();
    const { timestamps: ts, up: u, down: d } = dataRef.current;

    const opts: uPlot.Options = {
      width,
      height: 160,
      series: [
        {},
        {
          label: 'Upload',
          stroke: '#60a5fa',
          fill: (u: uPlot) => makeGradient(u, '#60a5fa', '20'),
          width: 2,
          value: (_u: uPlot, v: number | null) => formatBytes(v ?? 0),
        },
        {
          label: 'Download',
          stroke: '#34d399',
          fill: (u: uPlot) => makeGradient(u, '#34d399', '20'),
          width: 2,
          value: (_u: uPlot, v: number | null) => formatBytes(v ?? 0),
        },
      ],
      axes: [
        {
          stroke: 'transparent',
          ticks: { show: false },
          grid: { show: false },
        },
        {
          stroke: 'rgba(255,255,255,0.4)',
          ticks: { show: false },
          grid: { stroke: 'rgba(255,255,255,0.08)', width: 1 },
          values: (_u: uPlot, vals: (number | null)[]) => vals.map((v) => formatBytes(v ?? 0)),
          size: 80,
        },
      ],
      scales: { x: { time: true }, y: { auto: true } },
      cursor: { show: false },
      legend: { show: false },
      padding: [8, 0, 0, 0],
    };

    chartRef.current = new uPlot(opts, [ts, u, d], containerRef.current);
  }

  useEffect(() => {
    if (!containerRef.current) return;
    buildChart(containerRef.current.clientWidth);

    const observer = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width;
      if (width) buildChart(width);
    });
    observer.observe(containerRef.current);

    return () => {
      observer.disconnect();
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (chartRef.current) {
      chartRef.current.setData([timestamps, up, down]);
    }
  }, [timestamps, up, down]);

  return <div ref={containerRef} className="w-full" />;
}
