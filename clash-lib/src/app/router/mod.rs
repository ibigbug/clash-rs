use super::{
    dns::ThreadSafeDNSResolver,
    remote_content_manager::providers::{
        file_vehicle, http_vehicle,
        rule_provider::{RuleProviderImpl, ThreadSafeRuleProvider},
    },
};
use crate::{
    Error,
    app::router::rules::{
        domain::Domain, domain_keyword::DomainKeyword, domain_suffix::DomainSuffix,
        final_::Final, ipcidr::IpCidr, ruleset::RuleSet,
    },
    config::internal::{
        config::RuleProviderDef,
        rule::{RuleKind, RuleType},
    },
    print_and_exit,
    session::Session,
};

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use hyper::Uri;
use rules::domain_regex::DomainRegex;
use tracing::{error, info, trace};

pub(crate) mod rules;

use crate::common::{geodata::GeoDataLookup, mmdb::MmdbLookup};
pub use rules::RuleMatcher;

pub struct Router {
    rules: Vec<RuleEntry>,
    dns_resolver: ThreadSafeDNSResolver,

    country_mmdb: Option<MmdbLookup>,
    asn_mmdb: Option<MmdbLookup>,
    rule_providers: HashMap<String, ThreadSafeRuleProvider>,
}

pub type ArcRouter = Arc<Router>;

#[deprecated(
    note = "ThreadSafeRouter has been renamed to ArcRouter; use ArcRouter instead"
)]
pub type ThreadSafeRouter = ArcRouter;

const MATCH: &str = "MATCH";

impl Router {
    pub async fn new(
        rules: Vec<RuleType>,
        rule_providers: HashMap<String, RuleProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
        country_mmdb: Option<MmdbLookup>,
        asn_mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Self {
        let mut rule_provider_registry = HashMap::new();

        Self::load_rule_providers(
            rule_providers,
            &mut rule_provider_registry,
            dns_resolver.clone(),
            country_mmdb.clone(),
            geodata.clone(),
            cwd,
        )
        .await
        .ok();

        Self {
            rules: rules
                .into_iter()
                .map(|r| {
                    map_rule_entry(
                        r,
                        country_mmdb.clone(),
                        geodata.clone(),
                        Some(&rule_provider_registry),
                    )
                })
                .collect(),
            dns_resolver,

            country_mmdb,
            asn_mmdb,
            rule_providers: rule_provider_registry,
        }
    }

    pub fn get_rule_providers(&self) -> &HashMap<String, ThreadSafeRuleProvider> {
        &self.rule_providers
    }

    /// this mutates the session, attaching resolved IP and ASN
    pub async fn match_route(
        &self,
        sess: &mut Session,
    ) -> (&str, Option<&RuleEntry>) {
        let mut sess_resolved = false;

        for r in self.rules.iter() {
            // Resolve IP when needed
            if sess.destination.is_domain()
                && r.matcher.should_resolve_ip()
                && !sess_resolved
                && let Ok(Some(ip)) = self
                    .dns_resolver
                    .resolve(sess.destination.domain().unwrap(), false)
                    .await
            {
                sess.resolved_ip = Some(ip);
                sess_resolved = true;
            }

            // Lookup geo information with guard clause
            if let Some(ip) = sess.resolved_ip.or(sess.destination.ip()) {
                Self::populate_geo_for_ip(
                    ip,
                    &self.country_mmdb,
                    &self.asn_mmdb,
                    sess,
                );
            }

            if r.matcher.apply(sess) {
                info!(
                    "matched {} to target {}[{}]",
                    &sess,
                    r.matcher.target(),
                    r.matcher.type_name()
                );
                return (r.matcher.target(), Some(r));
            }
        }

        (MATCH, None)
    }

    /// Look up country code and ASN for an IP address.
    /// Uses `country_mmdb` for the ISO 3166-1 alpha-2 country code.
    /// For ASN, preserves the original strategy: try
    /// `asn_mmdb.lookup_country()` first (simplified/fast path, e.g.
    /// Country.mmdb), fall back to `asn_mmdb.lookup_asn()` for the org
    /// name.
    fn populate_geo_for_ip(
        ip: std::net::IpAddr,
        country_mmdb: &Option<MmdbLookup>,
        asn_mmdb: &Option<MmdbLookup>,
        sess: &mut Session,
    ) {
        // Preserve existing geo metadata — avoids overriding prior enrichment
        if sess.country.is_some() && sess.asn.is_some() {
            return;
        }

        if sess.country.is_none()
            && let Some(country_mmdb) = country_mmdb
        {
            match country_mmdb.lookup_country(ip) {
                Ok(country) => {
                    trace!("country for {} is {:?}", ip, country.country_code);
                    sess.country = Some(country.country_code);
                }
                Err(e) => {
                    trace!("failed to lookup country for {}: {}", ip, e);
                }
            }
        }

        if sess.asn.is_none()
            && let Some(asn_mmdb) = asn_mmdb
        {
            // try simplified mmdb first (e.g. Country.mmdb doubles as a fast
            // country-code lookup on the asn_mmdb slot)
            if let Ok(country) = asn_mmdb.lookup_country(ip) {
                sess.asn = Some(country.country_code);
                return;
            }
            // fall back to full ASN lookup
            match asn_mmdb.lookup_asn(ip) {
                Ok(asn) => {
                    trace!("asn for {} is {:?}", ip, asn);
                    sess.asn = Some(asn.asn_name);
                }
                Err(e) => {
                    trace!("failed to lookup ASN for {}: {}", ip, e);
                }
            }
        }
    }

    async fn load_rule_providers(
        rule_providers: HashMap<String, RuleProviderDef>,
        rule_provider_registry: &mut HashMap<String, ThreadSafeRuleProvider>,
        resolver: ThreadSafeDNSResolver,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        cwd: String,
    ) -> Result<(), Error> {
        for (name, provider) in rule_providers.into_iter() {
            match provider {
                RuleProviderDef::Http(http) => {
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<Uri>().unwrap_or_else(|_| {
                            print_and_exit!("invalid provider url: {}", http.url)
                        }),
                        http.path,
                        Some(cwd.clone()),
                        resolver.clone(),
                    );

                    // Default to yaml if not specified
                    let format = http.format.unwrap_or_default();
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        http.behavior,
                        format,
                        Some(Duration::from_secs(http.interval)),
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        http.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );

                    // Default to yaml if not specified
                    let format = file.format.unwrap_or_default();
                    // `interval` is optional for file providers: content is
                    // loaded at startup and live-reloaded via an OS file
                    // watcher, so polling is only an occasional fallback.
                    let interval = file.interval.map(Duration::from_secs);
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        file.behavior,
                        format,
                        interval,
                        Some(Arc::new(vehicle)),
                        mmdb.clone(),
                        geodata.clone(),
                        file.inline_rules,
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
                RuleProviderDef::Inline(inline) => {
                    let provider = RuleProviderImpl::new(
                        name.clone(),
                        inline.behavior,
                        Default::default(), /* format really doesn't matter for
                                             * inline rules */
                        None,
                        None,
                        mmdb.clone(),
                        geodata.clone(),
                        Some(inline.inline_rules),
                    );

                    rule_provider_registry.insert(name, Arc::new(provider));
                }
            }
        }

        for p in rule_provider_registry.values() {
            let p = p.clone();
            tokio::spawn(async move {
                info!("initializing rule provider {}", p.name());
                match p.initialize().await {
                    Ok(_) => {
                        info!("rule provider {} initialized", p.name());
                    }
                    Err(err) => {
                        error!(
                            "failed to initialize rule provider {}: {}",
                            p.name(),
                            err
                        );
                    }
                }
            });
        }

        Ok(())
    }

    /// API handlers
    pub fn get_all_rules(&self) -> &Vec<RuleEntry> {
        &self.rules
    }
}

pub struct RuleEntry {
    matcher: Box<dyn RuleMatcher>,
    interface: Option<String>,
}

impl RuleEntry {
    pub fn matcher(&self) -> &dyn RuleMatcher {
        self.matcher.as_ref()
    }

    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    pub fn as_map(
        &self,
    ) -> HashMap<String, Box<dyn erased_serde::Serialize + Send>> {
        let mut map = self.matcher.as_map();
        if let Some(interface) = &self.interface {
            map.insert("interface".to_string(), Box::new(interface.clone()));
        }
        map
    }
}

fn map_rule_entry(
    rule_type: RuleType,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> RuleEntry {
    let interface = rule_type.interface().map(str::to_owned);
    RuleEntry {
        matcher: map_rule_type(rule_type, mmdb, geodata, rule_provider_registry),
        interface,
    }
}

pub fn map_rule_type(
    rule_type: RuleType,
    mmdb: Option<MmdbLookup>,
    geodata: Option<GeoDataLookup>,
    rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
) -> Box<dyn RuleMatcher> {
    let (rule_kind, options) = rule_type.into_parts();
    let matcher: Box<dyn RuleMatcher> = match rule_kind {
        RuleKind::Domain { domain, target, .. } => {
            Box::new(Domain { domain, target }) as Box<dyn RuleMatcher>
        }
        RuleKind::DomainRegex { regex, target, .. } => {
            Box::new(DomainRegex { regex, target })
        }
        RuleKind::DomainSuffix {
            domain_suffix,
            target,
            ..
        } => Box::new(DomainSuffix {
            suffix: domain_suffix,
            target,
        }),
        RuleKind::DomainKeyword {
            domain_keyword,
            target,
            ..
        } => Box::new(DomainKeyword {
            keyword: domain_keyword,
            target,
        }),
        RuleKind::IpCidr { ipnet, target, .. } => Box::new(IpCidr {
            ipnet,
            target,
            no_resolve: options.no_resolve,
            match_src: false,
        }),
        RuleKind::SrcCidr { ipnet, target, .. } => Box::new(IpCidr {
            ipnet,
            target,
            no_resolve: options.no_resolve,
            match_src: true,
        }),

        RuleKind::GeoIP {
            target,
            country_code,
            ..
        } => Box::new(rules::geoip::GeoIP {
            target,
            country_code,
            no_resolve: options.no_resolve,
            mmdb: mmdb.clone(),
        }),
        RuleKind::GeoSite {
            target,
            country_code,
            ..
        } => {
            let res = rules::geodata::GeoSiteMatcher::new(
                country_code,
                target,
                geodata.as_ref(),
            )
            .unwrap();
            Box::new(res) as _
        }
        RuleKind::SRCPort {
            target,
            ports,
            raw_ports,
            ..
        } => Box::new(rules::port::Port {
            ports,
            raw: raw_ports,
            target,
            is_src: true,
        }),
        RuleKind::DSTPort {
            target,
            ports,
            raw_ports,
            ..
        } => Box::new(rules::port::Port {
            ports,
            raw: raw_ports,
            target,
            is_src: false,
        }),
        RuleKind::InType { in_type, target } => {
            Box::new(rules::in_type::InType { in_type, target })
        }
        RuleKind::InUser { user, target } => {
            Box::new(rules::in_user::InUser { user, target })
        }
        RuleKind::ProcessName {
            process_name,
            target,
            ..
        } => Box::new(rules::process::Process {
            name: process_name,
            target,
            name_only: true,
        }),
        RuleKind::ProcessPath {
            process_path,
            target,
            ..
        } => Box::new(rules::process::Process {
            name: process_path,
            target,
            name_only: false,
        }),
        RuleKind::RuleSet {
            rule_set, target, ..
        } => match rule_provider_registry {
            Some(rule_provider_registry) => Box::new(RuleSet::new(
                rule_set.clone(),
                target,
                rule_provider_registry
                    .get(&rule_set)
                    .unwrap_or_else(|| {
                        print_and_exit!("rule provider {} not found", rule_set)
                    })
                    .clone(),
            )),
            None => {
                // this is called in remote rule provider with no rule provider
                // registry, in this case, we should panic
                unreachable!("you shouldn't nest rule-set within another rule-set")
            }
        },
        RuleKind::Network {
            network, target, ..
        } => Box::new(rules::network::NetworkRule { network, target }),
        RuleKind::Composite {
            operator,
            expression,
            target,
            ..
        } => {
            match rules::composite::CompositeRule::new(
                &operator,
                &expression,
                &target,
                mmdb,
                geodata,
                rule_provider_registry,
            ) {
                Ok(rule) => Box::new(rule),
                Err(e) => {
                    error!(
                        "failed to create composite rule: {}, expression: {}. \
                         Using REJECT as fallback.",
                        e, expression
                    );
                    Box::new(Final {
                        target: "REJECT".to_string(),
                    })
                }
            }
        }
        RuleKind::Match { target, .. } => Box::new(Final { target }),
    };

    matcher
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Ok;

    use crate::{
        app::dns::{MockClashResolver, SystemResolver},
        common::{
            geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoData},
            http::new_http_client,
            mmdb::{DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL, Mmdb},
        },
        config::internal::rule::{RuleKind, RuleType},
        session::Session,
        tests::initialize,
    };

    #[test]
    fn test_interface_metadata_is_mapped() {
        let entry = super::map_rule_entry(
            RuleType::try_from("DOMAIN,example.com,PROXY,interface=en0".to_string())
                .unwrap(),
            None,
            None,
            None,
        );

        assert_eq!(entry.matcher().target(), "PROXY");
        assert_eq!(entry.interface(), Some("en0"));
    }

    #[tokio::test]
    async fn test_route_match() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|host, _| {
            if host == "china.com" {
                Ok(Some("114.114.114.114".parse().unwrap()))
            } else if host == "t.me" {
                Ok(Some("149.154.0.1".parse().unwrap()))
            } else if host == "git.io" {
                Ok(Some("8.8.8.8".parse().unwrap()))
            } else {
                Ok(None)
            }
        });
        let mock_resolver = Arc::new(mock_resolver);

        let real_resolver = Arc::new(SystemResolver::new(false).unwrap());

        let client = new_http_client(real_resolver.clone(), None).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();

        let mmdb = Mmdb::new(
            temp_dir.path().join("mmdb.mmdb"),
            DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let client = new_http_client(real_resolver.clone(), None).unwrap();

        let geodata = GeoData::new(
            temp_dir.path().join("geodata.geodata"),
            DEFAULT_GEOSITE_DOWNLOAD_URL.to_string(),
            client,
        )
        .await
        .unwrap();

        let router = super::Router::new(
            vec![
                RuleKind::GeoIP {
                    target: "DIRECT".to_string(),
                    country_code: "CN".to_string(),
                }
                .into(),
                RuleKind::DomainRegex {
                    regex: regex::Regex::new(r"^regex").unwrap(),
                    target: "regex-match".to_string(),
                }
                .into(),
                RuleKind::DomainSuffix {
                    domain_suffix: "t.me".to_string(),
                    target: "DS".to_string(),
                }
                .into(),
                RuleKind::IpCidr {
                    ipnet: "149.154.0.0/16".parse().unwrap(),
                    target: "IC".to_string(),
                }
                .into(),
                RuleKind::DomainSuffix {
                    domain_suffix: "git.io".to_string(),
                    target: "DS2".to_string(),
                }
                .into(),
            ],
            Default::default(),
            mock_resolver,
            Some(Arc::new(mmdb)),
            None,
            Some(Arc::new(geodata)),
            temp_dir.path().to_str().unwrap().to_string(),
        )
        .await;

        let cases = vec![
            ("china.com", "DIRECT", "should resolve and match IP"),
            ("regex", "regex-match", "should match regex"),
            ("t.me", "DS", "should match domain"),
            (
                "git.io",
                "DS2",
                "should still match domain after previous rule resolved IP and non \
                 match",
            ),
            (
                "no-match",
                "MATCH",
                "should fallback to MATCH when nothing matched",
            ),
            ("149.154.0.1", "IC", "should match CIDR"),
        ];

        for (domain, target, desc) in cases {
            assert_eq!(
                router
                    .match_route(&mut Session {
                        destination: crate::session::SocksAddr::Domain(
                            domain.to_string(),
                            1111
                        ),
                        ..Default::default()
                    })
                    .await
                    .0,
                target,
                "{}",
                desc
            );
        }
    }

    #[tokio::test]
    async fn test_network_rule() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| Ok(None));
        let mock_resolver = Arc::new(mock_resolver);

        let router = super::Router::new(
            vec![
                RuleKind::Network {
                    network: crate::session::Network::Tcp,
                    target: "TCP-PROXY".to_string(),
                }
                .into(),
                RuleKind::Network {
                    network: crate::session::Network::Udp,
                    target: "UDP-PROXY".to_string(),
                }
                .into(),
            ],
            Default::default(),
            mock_resolver,
            None,
            None,
            None,
            std::env::temp_dir().to_str().unwrap().to_string(),
        )
        .await;

        // Test TCP network rule
        let mut tcp_session = Session {
            network: crate::session::Network::Tcp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".to_string(),
                443,
            ),
            ..Default::default()
        };
        assert_eq!(
            router.match_route(&mut tcp_session).await.0,
            "TCP-PROXY",
            "should match TCP network rule"
        );

        // Test UDP network rule
        let mut udp_session = Session {
            network: crate::session::Network::Udp,
            destination: crate::session::SocksAddr::Domain(
                "example.com".to_string(),
                53,
            ),
            ..Default::default()
        };
        assert_eq!(
            router.match_route(&mut udp_session).await.0,
            "UDP-PROXY",
            "should match UDP network rule"
        );
    }
}
