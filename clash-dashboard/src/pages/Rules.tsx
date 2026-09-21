import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getRules, getRuleProviders, updateRuleProvider, getRuleProviderRules, matchRuleProvider } from '../lib/api';
import { RefreshCw, Search } from 'lucide-react';
import type { RuleProvider } from '../lib/api';

function getRuleTypeBadgeStyle(type: string): { background: string; color: string } {
  switch (type) {
    case 'Domain':           return { background: 'rgba(0,113,227,0.12)',   color: '#0071e3' };
    case 'DomainSuffix':     return { background: 'rgba(0,149,255,0.12)',   color: '#0095ff' };
    case 'DomainKeyword':    return { background: 'rgba(10,132,255,0.12)',  color: '#0a84ff' };
    case 'DomainRegex':      return { background: 'rgba(50,173,230,0.12)',  color: '#32ade6' };
    case 'IPCIDR':           return { background: 'rgba(52,199,89,0.12)',   color: '#34c759' };
    case 'IPCIDR6':          return { background: 'rgba(48,209,88,0.12)',   color: '#30d158' };
    case 'IpAsn':            return { background: 'rgba(37,162,68,0.12)',   color: '#25a244' };
    case 'GeoIP':            return { background: 'rgba(255,149,0,0.12)',   color: '#ff9500' };
    case 'GeoSite':          return { background: 'rgba(244,160,21,0.12)',  color: '#f4a015' };
    case 'RuleSet':          return { background: 'rgba(175,82,222,0.12)',  color: '#af52de' };
    case 'ProcessName':      return { background: 'rgba(255,69,58,0.12)',   color: '#ff453a' };
    case 'ProcessPath':      return { background: 'rgba(255,99,82,0.12)',   color: '#ff6352' };
    case 'Port':             return { background: 'rgba(162,132,94,0.12)',  color: '#a2845e' };
    case 'Network':          return { background: 'rgba(100,100,100,0.12)', color: '#636366' };
    case 'AND':              return { background: 'rgba(88,86,214,0.12)',   color: '#5856d6' };
    case 'OR':               return { background: 'rgba(88,86,214,0.12)',   color: '#5856d6' };
    case 'NOT':              return { background: 'rgba(88,86,214,0.12)',   color: '#5856d6' };
    case 'Match':
    case 'Final':            return { background: 'rgba(142,142,147,0.12)', color: '#636366' };
    default:                 return { background: 'var(--color-fill-medium)',   color: 'var(--color-text-tertiary)' };
  }
}

function RuleProviderRulesPanel({ name, behavior }: { name: string; behavior?: string }) {
  const [matchInput, setMatchInput] = useState('');
  const [matchTarget, setMatchTarget] = useState<string | null>(null);

  const { data: rulesData, isLoading: rulesLoading, isError: rulesError } = useQuery({
    queryKey: ['rule-provider-rules', name],
    queryFn: () => getRuleProviderRules(name),
  });

  const { data: matchData, isLoading: matchLoading, isError: matchError } = useQuery({
    queryKey: ['rule-provider-match', name, matchTarget],
    queryFn: () => matchRuleProvider(name, matchTarget!),
    enabled: matchTarget !== null && matchTarget.trim().length > 0,
  });

  const providerRules = rulesData?.rules ?? [];
  const behaviorLower = behavior?.toLowerCase();
  const canShowRules = behaviorLower === 'classical';

  function handleMatchSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (matchInput.trim()) setMatchTarget(matchInput.trim());
  }

  return (
    <div className="space-y-3">
      <form onSubmit={handleMatchSubmit} className="flex gap-2 items-center">
        <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-xl border"
          style={{ background: 'var(--color-fill-subtle)', borderColor: 'var(--color-border)' }}>
          <Search size={13} style={{ color: 'var(--color-text-tertiary)', flexShrink: 0 }} />
          <input
            type="text"
            aria-label={`Rule match target for ${name}`}
            value={matchInput}
            onChange={(e) => setMatchInput(e.target.value)}
            placeholder={behaviorLower === 'ipcidr' ? 'Test IP (e.g. 8.8.8.8)' : 'Test domain or IP'}
            className="flex-1 bg-transparent outline-none text-[13px]"
            style={{ color: 'var(--color-text-primary)' }}
          />
        </div>
        <button
          type="submit"
          disabled={!matchInput.trim()}
          className="px-3 py-2 rounded-xl text-[12px] font-medium disabled:opacity-40 transition-colors"
          style={{ background: 'rgba(0,113,227,0.1)', color: '#0071e3' }}
        >
          Test
        </button>
        {matchTarget !== null && (
          <div className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-[12px] font-semibold flex-shrink-0"
            style={
              matchLoading ? { background: 'var(--color-fill-subtle)', color: 'var(--color-text-tertiary)' }
              : matchError  ? { background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }
              : matchData?.match ? { background: 'rgba(52,199,89,0.12)', color: '#34c759' }
              : { background: 'rgba(255,59,48,0.1)', color: '#ff3b30' }
            }
          >
            {matchLoading ? '…' : matchError ? '⚠ Error' : matchData?.match ? '✓ Match' : '✗ No match'}
            {matchData?.match && matchData?.rule && (
              <span className="font-mono font-normal text-[10px] px-1.5 py-0.5 rounded-md ml-1"
                style={{ background: 'rgba(52,199,89,0.15)' }}>
                {matchData.rule}
              </span>
            )}
          </div>
        )}
      </form>

      {canShowRules && (
        rulesLoading ? (
          <div className="text-[13px] py-1" style={{ color: 'var(--color-text-tertiary)' }}>Loading rules…</div>
        ) : rulesError ? (
          <div className="text-[13px] py-1" style={{ color: '#ff3b30' }}>Failed to load rules.</div>
        ) : providerRules.length === 0 ? (
          <div className="text-[13px] py-1 italic" style={{ color: 'var(--color-text-tertiary)' }}>No rules loaded</div>
        ) : (
          <div className="max-h-64 overflow-y-auto space-y-1 pr-1">
            {providerRules.map((rule, i) => {
              const [type, ...rest] = rule.split(',');
              const payload = rest.join(',');
              return (
                <div key={i} className="flex items-center gap-2 px-2 py-1 rounded-lg text-[12px]"
                  style={{ background: 'var(--color-fill-subtle)' }}>
                  <span className="font-mono font-semibold px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{ background: 'rgba(255,149,0,0.12)', color: '#ff9500', fontSize: 10 }}>
                    {type}
                  </span>
                  <span className="font-mono truncate" style={{ color: 'var(--color-text-primary)' }}>{payload}</span>
                </div>
              );
            })}
            {providerRules.length >= 500 && (
              <div className="text-[11px] text-center pt-1" style={{ color: 'var(--color-text-tertiary)' }}>
                Showing first 500 rules
              </div>
            )}
          </div>
        )
      )}

      {!canShowRules && (
        <div className="text-[12px] italic" style={{ color: 'var(--color-text-tertiary)' }}>
          Rule entries are not enumerable for {behavior} providers — use the tester above.
        </div>
      )}
    </div>
  );
}

export function Rules() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [updatingRuleProviders, setUpdatingRuleProviders] = useState<Set<string>>(new Set());
  const [expandedRuleProviders, setExpandedRuleProviders] = useState<Set<string>>(new Set());

  const { data, isLoading, isError } = useQuery({ queryKey: ['rules'], queryFn: getRules });
  const { data: ruleData, isLoading: ruleIsLoading, isError: ruleIsError } = useQuery({
    queryKey: ['rule-providers'],
    queryFn: getRuleProviders,
    refetchInterval: 60000,
  });

  const rules = data?.rules ?? [];
  const filtered = rules.filter(
    (r) =>
      r.type.toLowerCase().includes(search.toLowerCase()) ||
      (r.payload ?? '').toLowerCase().includes(search.toLowerCase()) ||
      r.proxy.toLowerCase().includes(search.toLowerCase())
  );

  const ruleProviders = Object.values(ruleData?.providers ?? {})
    .filter((p) => p.vehicleType !== 'Compatible' && p.vehicleType !== 'Inline')
    .sort((a, b) => a.name.localeCompare(b.name));

  function toggleRuleProviderExpanded(name: string) {
    setExpandedRuleProviders((prev) => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }

  async function runRuleUpdate(provider: RuleProvider) {
    setUpdatingRuleProviders((s) => new Set(s).add(provider.name));
    try {
      await updateRuleProvider(provider.name);
      await queryClient.invalidateQueries({ queryKey: ['rule-providers'] });
    } catch (err) {
      console.error(`Failed to update rule provider "${provider.name}":`, err);
    } finally {
      setUpdatingRuleProviders((s) => { const next = new Set(s); next.delete(provider.name); return next; });
    }
  }

  function getBehaviorStyle(behavior?: string): { background: string; color: string } {
    switch (behavior?.toLowerCase()) {
      case 'domain':    return { background: 'rgba(52,199,89,0.12)',  color: '#34c759' };
      case 'ipcidr':    return { background: 'rgba(0,113,227,0.12)',  color: '#0071e3' };
      case 'classical': return { background: 'rgba(255,149,0,0.12)', color: '#ff9500' };
      default:          return { background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' };
    }
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>Rules</h1>
        <span className="text-[13px]" style={{ color: 'var(--color-text-tertiary)' }}>{filtered.length} / {rules.length}</span>
      </div>

      <div className="relative">
        <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--color-text-tertiary)' }} />
        <input
          type="text"
          placeholder="Filter rules…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 rounded-xl text-[15px] focus:outline-none transition-shadow"
          style={{
            background: 'var(--color-input-bg)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-primary)',
          }}
        />
      </div>

      {isLoading ? (
        <div className="text-[15px]" style={{ color: 'var(--color-text-secondary)' }}>Loading rules…</div>
      ) : isError ? (
        <div className="liquid-glass-card rounded-xl p-6 text-center text-[15px]" style={{ color: '#ff3b30' }}>
          Failed to load rules. Check your connection and API secret.
        </div>
      ) : (
        <div
          className="liquid-glass-card rounded-xl overflow-hidden"
          style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
        >
          {filtered.length === 0 ? (
            <div className="py-12 text-center text-[15px]" style={{ color: 'var(--color-text-tertiary)' }}>
              No rules match your search
            </div>
          ) : (
            filtered.map((rule, i) => {
              const typeStyle = getRuleTypeBadgeStyle(rule.type);
              return (
              <div
                key={i}
                className="flex items-center gap-3 px-4"
                style={{
                  minHeight: 48,
                  borderBottom: i < filtered.length - 1 ? '1px solid var(--color-separator-subtle)' : 'none',
                }}
              >
                <span
                  className="font-mono text-[11px] flex-shrink-0 w-8 text-right"
                  style={{ color: 'var(--color-text-tertiary)' }}
                >
                  {i + 1}
                </span>
                <span
                  className="text-[11px] font-semibold tracking-wider px-2 py-0.5 rounded-full flex-shrink-0"
                  style={{ background: typeStyle.color + '22', color: typeStyle.color }}
                >
                  {rule.type}
                </span>
                <span
                  className="flex-1 font-mono text-[13px] truncate"
                  style={{ color: 'var(--color-text-primary)' }}
                >
                  {rule.payload || '—'}
                </span>
                <span
                  className="text-[13px] font-medium flex-shrink-0"
                  style={{ color: 'var(--color-text-primary)' }}
                >
                  {rule.proxy}
                </span>
              </div>
              );
            })
          )}
        </div>
      )}

      {/* Rule Providers Section */}
      <div className="flex items-center justify-between pt-4">
        <h2 className="text-xl font-semibold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>Rule Providers</h2>
        <span className="text-[13px]" style={{ color: 'var(--color-text-tertiary)' }}>
          {ruleProviders.length} provider{ruleProviders.length !== 1 ? 's' : ''}
        </span>
      </div>

      {ruleIsLoading ? (
        <div className="text-[15px]" style={{ color: 'var(--color-text-secondary)' }}>Loading rule providers…</div>
      ) : ruleIsError ? (
        <div className="text-[15px]" style={{ color: '#ff3b30' }}>Failed to load rule providers. Check your API connection.</div>
      ) : ruleProviders.length === 0 ? (
        <div className="liquid-glass-card rounded-2xl p-8 flex flex-col items-center gap-2 text-center">
          <div className="text-3xl">📋</div>
          <div className="text-[15px] font-semibold" style={{ color: 'var(--color-text-primary)' }}>No Rule Providers</div>
          <div className="text-[13px]" style={{ color: 'var(--color-text-secondary)' }}>
            Add rule providers to your config to see them here.
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {ruleProviders.map((provider) => {
            const isUpdating = updatingRuleProviders.has(provider.name);
            const isExpanded = expandedRuleProviders.has(provider.name);
            const behaviorStyle = getBehaviorStyle(provider.behavior);
            return (
              <div key={provider.name}
                className="liquid-glass-card rounded-xl overflow-hidden"
                style={{ boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}
              >
                <div className="flex">
                  <div className="w-1 flex-shrink-0" style={{ background: behaviorStyle.color }} />
                  <div className="flex-1">
                    <div
                      className="px-4 py-3 flex items-center justify-between cursor-pointer"
                      style={{ minHeight: 56 }}
                      role="button"
                      tabIndex={0}
                      aria-expanded={isExpanded}
                      onClick={() => toggleRuleProviderExpanded(provider.name)}
                      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && toggleRuleProviderExpanded(provider.name)}
                    >
                      <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                        <span className="font-semibold text-[15px] truncate" style={{ color: 'var(--color-text-primary)' }}>
                          {provider.name}
                        </span>
                        <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                          style={{ background: 'var(--color-fill-medium)', color: 'var(--color-text-secondary)' }}>
                          {provider.vehicleType}
                        </span>
                        {provider.behavior && (
                          <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
                            style={behaviorStyle}>
                            {provider.behavior}
                          </span>
                        )}
                        {provider.ruleCount !== undefined && (
                          <span className="text-[11px] px-2 py-0.5 rounded-full flex-shrink-0"
                            style={{ background: 'var(--color-fill-subtle)', color: 'var(--color-text-tertiary)' }}>
                            {provider.ruleCount} rule{provider.ruleCount !== 1 ? 's' : ''}
                          </span>
                        )}
                        {provider.updatedAt && (
                          <span className="text-[11px] truncate hidden sm:inline" style={{ color: 'var(--color-text-tertiary)' }}>
                            Updated {new Date(provider.updatedAt).toLocaleTimeString()}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); runRuleUpdate(provider); }}
                          disabled={isUpdating}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium disabled:opacity-50 transition-colors"
                          style={{ background: 'rgba(0,113,227,0.1)', color: '#0071e3' }}
                        >
                          <RefreshCw size={12} className={isUpdating ? 'animate-spin' : ''} />
                          {isUpdating ? 'Updating…' : 'Update'}
                        </button>
                        <span style={{ color: 'var(--color-text-secondary)', fontSize: 16 }}>{isExpanded ? '▲' : '▼'}</span>
                      </div>
                    </div>
                    {isExpanded && (
                      <div className="px-4 pb-4 border-t" style={{ borderColor: 'var(--color-separator)' }}>
                        <div className="pt-3">
                          <RuleProviderRulesPanel name={provider.name} behavior={provider.behavior} />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
