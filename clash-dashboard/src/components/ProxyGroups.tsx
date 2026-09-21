import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getProxies, getProxyProviders, selectProxy, getGroupDelay } from '../lib/api';
import { RefreshCw, ChevronDown, ChevronUp, Check } from 'lucide-react';
import type { Proxy } from '../lib/api';

const TEST_URL = 'http://www.gstatic.com/generate_204';
const TEST_TIMEOUT = 5000;
const GROUP_TYPES = ['Selector', 'URLTest', 'Fallback', 'LoadBalance'];

function getLatencyColor(delay: number | undefined): string {
  if (!delay || delay === 0) return '#8e8e93';
  if (delay < 200) return '#34c759';
  if (delay < 500) return '#ff9500';
  return '#ff3b30';
}

function getGroupAccentColor(type: string): string {
  if (type === 'Selector') return '#0071e3';
  if (type === 'URLTest') return '#34c759';
  if (type === 'Fallback') return '#ff9500';
  if (type === 'LoadBalance') return '#af52de';
  return '#8e8e93';
}

function getTypeBadgeStyle(type: string): { background: string; color: string } {
  if (type === 'Selector') return { background: 'rgba(0,113,227,0.1)', color: '#0071e3' };
  if (type === 'URLTest') return { background: 'rgba(52,199,89,0.1)', color: '#34c759' };
  if (type === 'Fallback') return { background: 'rgba(255,149,0,0.1)', color: '#ff9500' };
  if (type === 'LoadBalance') return { background: 'rgba(175,82,222,0.1)', color: '#af52de' };
  return { background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' };
}

function getLastDelay(history: Proxy['history']): number | undefined {
  if (!history || history.length === 0) return undefined;
  return history[history.length - 1]?.delay;
}

interface ProxyGroupsProps {
  mode: string;
}

export function ProxyGroups({ mode }: ProxyGroupsProps) {
  const queryClient = useQueryClient();
  const [testingGroups, setTestingGroups] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [groupLatencyMap, setGroupLatencyMap] = useState<Record<string, number>>({});

  const { data, isLoading } = useQuery({
    queryKey: ['proxies'],
    queryFn: getProxies,
    refetchInterval: 30000,
  });

  const { data: providersData } = useQuery({
    queryKey: ['providers'],
    queryFn: getProxyProviders,
    refetchInterval: 60000,
  });

  const selectMutation = useMutation({
    mutationFn: ({ group, proxy }: { group: string; proxy: string }) =>
      selectProxy(group, proxy),
    onMutate: async ({ group, proxy }) => {
      await queryClient.cancelQueries({ queryKey: ['proxies'] });
      const previous = queryClient.getQueryData<{ proxies: Record<string, Proxy> }>(['proxies']);
      queryClient.setQueryData<{ proxies: Record<string, Proxy> }>(['proxies'], (old) => {
        if (!old) return old;
        return {
          ...old,
          proxies: { ...old.proxies, [group]: { ...old.proxies[group], now: proxy } },
        };
      });
      return { previous };
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.previous) queryClient.setQueryData(['proxies'], ctx.previous);
      queryClient.invalidateQueries({ queryKey: ['proxies'] });
    },
  });

  const proxies = data?.proxies ?? {};

  // Merge provider proxies so group chips show latency for provider-sourced members
  const mergedProxies: Record<string, Proxy> = {};
  for (const p of Object.values(providersData?.providers ?? {})) {
    for (const px of p.proxies ?? []) mergedProxies[px.name] = px;
  }
  Object.assign(mergedProxies, proxies); // registry entries take precedence

  const globalGroup = proxies['GLOBAL'];
  const sortIndex: string[] = globalGroup?.all ?? [];

  function sortByConfig<T extends { name: string }>(items: T[]): T[] {
    return [...items].sort((a, b) => {
      const ia = sortIndex.indexOf(a.name);
      const ib = sortIndex.indexOf(b.name);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.name.localeCompare(b.name);
    });
  }

  const allGroups = sortByConfig(
    Object.values(proxies).filter((p) => GROUP_TYPES.includes(p.type))
  );

  const groups = mode === 'global'
    ? allGroups.filter((g) => g.name.toUpperCase() === 'GLOBAL')
    : mode === 'rule'
      ? allGroups.filter((g) => g.name.toUpperCase() !== 'GLOBAL')
      : [];

  function toggleExpanded(name: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }

  async function testGroupDelay(group: Proxy) {
    if (!group.all) return;
    setTestingGroups((s) => new Set(s).add(group.name));
    setExpanded((prev) => new Set(prev).add(group.name));
    try {
      const result = await getGroupDelay(group.name, TEST_URL, TEST_TIMEOUT);
      // result is { [groupName]: latencyMs } — store the group's own latency
      const ms = result[group.name];
      if (ms !== undefined) {
        setGroupLatencyMap((prev) => ({ ...prev, [group.name]: ms }));
      }
      await Promise.all([
        queryClient.refetchQueries({ queryKey: ['proxies'] }),
        queryClient.refetchQueries({ queryKey: ['providers'] }),
      ]);
    } catch {
      // leave existing latency values unchanged on error
    } finally {
      setTestingGroups((s) => { const next = new Set(s); next.delete(group.name); return next; });
    }
  }

  if (isLoading) {
    return <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>Loading proxies…</div>;
  }

  if (mode === 'direct' || groups.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-4 text-center">
        <div className="text-2xl">⚡️</div>
        <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
          {mode === 'direct' ? 'Direct mode — no proxy groups' : 'No groups for this mode'}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {groups.map((group) => {
        const isTesting = testingGroups.has(group.name);
        const isExpanded = expanded.has(group.name);
        const isSelector = group.type === 'Selector';
        const accentColor = getGroupAccentColor(group.type);
        const typeBadge = getTypeBadgeStyle(group.type);
        // Group's own latency: from last test result, falling back to group history
        const groupProxy = proxies[group.name];
        const historyLatency = getLastDelay(groupProxy?.history);
        const headerLatency = groupLatencyMap[group.name] ?? historyLatency;
        const headerLatencyColor = getLatencyColor(headerLatency);

        return (
          <div
            key={group.name}
            className="rounded-xl overflow-hidden border"
            style={{ borderColor: 'var(--color-separator)', background: 'var(--color-proxy-card-bg)' }}
          >
            <div className="flex">
              <div className="w-1 flex-shrink-0" style={{ background: accentColor }} />
              <div className="flex-1">
                <div
                  className="px-4 py-3 flex items-center justify-between cursor-pointer"
                  style={{ minHeight: 48 }}
                  onClick={() => toggleExpanded(group.name)}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="font-semibold text-[14px] truncate" style={{ color: 'var(--color-text-primary)' }}>
                      {group.name}
                    </span>
                    <span
                      className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                      style={typeBadge}
                    >
                      {group.type}
                    </span>
                    {group.now && (
                      <span className="text-[13px] truncate" style={{ color: 'var(--color-text-secondary)' }}>
                        {group.now}
                      </span>
                    )}
                    {headerLatency !== undefined && (
                      <span className="text-[11px] font-mono flex-shrink-0" style={{ color: headerLatencyColor }}>
                        {headerLatency === 0 ? 'Timeout' : `${headerLatency}ms`}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); testGroupDelay(group); }}
                      disabled={isTesting}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium disabled:opacity-50"
                      style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-secondary)' }}
                    >
                      <RefreshCw size={11} className={isTesting ? 'animate-spin' : ''} />
                      {isTesting ? 'Testing…' : 'Test'}
                    </button>
                    {isExpanded
                      ? <ChevronUp size={15} style={{ color: 'var(--color-text-secondary)' }} />
                      : <ChevronDown size={15} style={{ color: 'var(--color-text-secondary)' }} />
                    }
                  </div>
                </div>

                {isExpanded && (
                  <div className="px-4 pb-4 border-t pt-3" style={{ borderColor: 'var(--color-separator)' }}>
                    {!isSelector && (
                      <p className="text-[11px] mb-2.5" style={{ color: 'var(--color-text-tertiary)' }}>
                        Auto-selected — click to force override
                      </p>
                    )}
                    <div className="grid grid-cols-3 sm:grid-cols-4 gap-1.5">
                      {group.all?.map((proxyName) => {
                        const proxy = mergedProxies[proxyName];
                        const history = proxy?.history ?? [];
                        const latency = getLastDelay(history);
                        const isSelected = group.now === proxyName;
                        const latencyColor = getLatencyColor(latency);
                        const inner = (
                          <>
                            <div className="flex items-center gap-1 mb-0.5">
                              {isSelected && <Check size={11} className="text-white flex-shrink-0" />}
                              <div
                                className="text-[12px] font-medium truncate"
                                style={{ color: isSelected ? 'white' : 'var(--color-text-primary)' }}
                              >
                                {proxyName}
                              </div>
                            </div>
                            <div className="flex items-center gap-1">
                              <div
                                className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                                style={{ background: isSelected ? 'rgba(255,255,255,0.7)' : latencyColor }}
                              />
                              <span
                                className="text-[10px] font-mono"
                                style={{ color: isSelected ? 'rgba(255,255,255,0.8)' : latencyColor }}
                              >
                                {latency === undefined ? '—' : latency === 0 ? 'Timeout' : `${latency}ms`}
                              </span>
                            </div>
                          </>
                        );

                        const chipStyle = {
                          ...(isSelected
                            ? { background: '#0071e3', borderColor: '#0071e3' }
                            : { background: 'var(--color-input-focus-bg)', borderColor: 'var(--color-separator)' }),
                        };

                        return isSelector ? (
                          <button
                            key={proxyName}
                            onClick={() => selectMutation.mutate({ group: group.name, proxy: proxyName })}
                            className="px-3 py-2 rounded-lg text-left border transition-all"
                            style={{ ...chipStyle, cursor: 'pointer' }}
                          >
                            {inner}
                          </button>
                        ) : (
                          <div
                            key={proxyName}
                            className="px-3 py-2 rounded-lg text-left border"
                            style={chipStyle}
                          >
                            {inner}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
