use std::collections::HashMap;

use thiserror::Error;
use url::{Host, Url};
use zeroconf_tokio::{
    MdnsBrowser, MdnsBrowserAsync, MdnsService, MdnsServiceAsync, ServiceDiscovery, ServiceType, TxtRecord,
    prelude::{TMdnsBrowser, TMdnsService, TTxtRecord},
};

use crate::{Deployment, S2Role};

#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum BuilderError {
    #[error("Invalid url provided")]
    InvalidUrl,
}

#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum Error {
    #[error("mDNS failed")]
    MdnsError,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiscoverableS2Endpoint {
    endpoint_name: Option<String>,
    endpoint_logo_url: Option<String>,
    deployment: Deployment,
    pairing_url: Option<String>,
    longpolling_url: Option<String>,
    roles: Vec<S2Role>,
}

impl DiscoverableS2Endpoint {
    pub fn deployment(&self) -> Deployment {
        self.deployment
    }

    pub fn pairing_url(&self) -> Option<&str> {
        self.pairing_url.as_deref()
    }

    pub fn longpolling_url(&self) -> Option<&str> {
        self.longpolling_url.as_deref()
    }

    pub fn endpoint_name(&self) -> Option<&str> {
        self.endpoint_name.as_deref()
    }

    pub fn endpoint_logo_url(&self) -> Option<&str> {
        self.endpoint_logo_url.as_deref()
    }

    pub fn build_with_pairing(roles: Vec<S2Role>, pairing_url: String) -> Result<DiscoverableS2EndpointBuilder, BuilderError> {
        let parsed_url: Url = pairing_url.parse().map_err(|_| BuilderError::InvalidUrl)?;
        let host = parsed_url.host().ok_or(BuilderError::InvalidUrl)?;
        let deployment = Deployment::try_from(host).map_err(|_| BuilderError::InvalidUrl)?;

        Ok(DiscoverableS2EndpointBuilder {
            endpoint_name: None,
            endpoint_logo_url: None,
            deployment,
            pairing_url: Some(pairing_url),
            longpolling_url: None,
            roles,
        })
    }

    pub fn build_with_longpolling(roles: Vec<S2Role>, longpolling_url: String) -> Result<DiscoverableS2EndpointBuilder, BuilderError> {
        let parsed_url: Url = longpolling_url.parse().map_err(|_| BuilderError::InvalidUrl)?;
        let host = parsed_url.host().ok_or(BuilderError::InvalidUrl)?;
        let deployment = Deployment::try_from(host).map_err(|_| BuilderError::InvalidUrl)?;

        Ok(DiscoverableS2EndpointBuilder {
            endpoint_name: None,
            endpoint_logo_url: None,
            deployment,
            pairing_url: None,
            longpolling_url: Some(longpolling_url),
            roles,
        })
    }

    pub(crate) fn from_discovery(service_discovery: &ServiceDiscovery) -> Option<Self> {
        let txt = service_discovery.txt().as_ref()?;

        if txt.get("txtver").as_deref() != Some("1") {
            return None;
        }
        let deployment = match txt.get("deployment").as_deref() {
            Some("WAN") => Some(Deployment::Wan),
            Some("LAN") => Some(Deployment::Lan),
            _ => None,
        }?;
        let roles = service_discovery
            .service_type()
            .sub_types()
            .iter()
            .filter_map(|v| match v.as_str() {
                "cem" => Some(S2Role::Cem),
                "rm" => Some(S2Role::Rm),
                _ => None,
            })
            .collect::<Vec<_>>();

        let mut endpoint = DiscoverableS2Endpoint {
            endpoint_name: None,
            endpoint_logo_url: None,
            deployment,
            pairing_url: None,
            longpolling_url: None,
            roles,
        };

        let host_matches_deployment = |url: url::Url| {
            url.host_str().map(|v| v.ends_with(".local") || v.ends_with(".local.")) == Some(matches!(deployment, Deployment::Lan))
        };

        if let Some(pairing_url) = txt.get("pairingUrl") {
            let url = pairing_url.parse::<Url>().ok()?;

            if !host_matches_deployment(url) {
                return None;
            }

            endpoint.pairing_url = Some(pairing_url);
        }

        if let Some(longpolling_url) = txt.get("longpollingUrl") {
            let url = longpolling_url.parse::<Url>().ok()?;

            if !host_matches_deployment(url) {
                return None;
            }

            endpoint.longpolling_url = Some(longpolling_url);
        }

        if let Some(endpoint_name) = txt.get("e_name") {
            endpoint.endpoint_name = Some(endpoint_name);
        }

        if let Some(endpoint_logo_url) = txt.get("e_logoUrl") {
            endpoint.endpoint_logo_url = Some(endpoint_logo_url);
        }

        if endpoint.pairing_url.is_none() && endpoint.longpolling_url.is_none() {
            return None;
        }

        Some(endpoint)
    }
}

pub struct DiscoverableS2EndpointBuilder {
    endpoint_name: Option<String>,
    endpoint_logo_url: Option<String>,
    deployment: Deployment,
    pairing_url: Option<String>,
    longpolling_url: Option<String>,
    roles: Vec<S2Role>,
}

impl DiscoverableS2EndpointBuilder {
    pub fn build(self) -> DiscoverableS2Endpoint {
        DiscoverableS2Endpoint {
            endpoint_name: self.endpoint_name,
            endpoint_logo_url: self.endpoint_logo_url,
            deployment: self.deployment,
            pairing_url: self.pairing_url,
            longpolling_url: self.longpolling_url,
            roles: self.roles,
        }
    }

    pub fn with_pairing_url(mut self, pairing_url: String) -> Result<Self, BuilderError> {
        let parsed_url: Url = pairing_url.parse().map_err(|_| BuilderError::InvalidUrl)?;
        match parsed_url.host().ok_or(BuilderError::InvalidUrl)? {
            Host::Domain(domain)
                if (domain.ends_with(".local") || domain.ends_with(".local.")) == matches!(self.deployment, Deployment::Lan) =>
            {
                self.pairing_url = Some(pairing_url);
                Ok(self)
            }
            _ => Err(BuilderError::InvalidUrl),
        }
    }

    pub fn with_longpolling_url(mut self, longpolling_url: String) -> Result<Self, BuilderError> {
        let parsed_url: Url = longpolling_url.parse().map_err(|_| BuilderError::InvalidUrl)?;
        match parsed_url.host().ok_or(BuilderError::InvalidUrl)? {
            Host::Domain(domain)
                if (domain.ends_with(".local") || domain.ends_with(".local.")) == matches!(self.deployment, Deployment::Lan) =>
            {
                self.pairing_url = Some(longpolling_url);
                Ok(self)
            }
            _ => Err(BuilderError::InvalidUrl),
        }
    }

    pub fn with_endpoint_name(mut self, name: String) -> Self {
        self.endpoint_name = Some(name);
        self
    }

    pub fn with_endpoint_logo_url(mut self, logo_url: String) -> Self {
        self.endpoint_logo_url = Some(logo_url);
        self
    }
}

pub struct S2Advertisement {
    // Kept around for the shutdown on drop
    advertisement: MdnsServiceAsync,
}

impl S2Advertisement {
    pub async fn stop(mut self) {
        self.advertisement.shutdown().await.ok();
    }
}

pub async fn advertise(port: u16, endpoint: DiscoverableS2Endpoint) -> Result<S2Advertisement, Error> {
    // The unwrap here is fine as the arguments always contain valid characters.
    let mut service = MdnsService::new(
        ServiceType::with_sub_types("s2emp", "tcp", endpoint.roles.iter().map(|v| v.service_subtype()).collect()).unwrap(),
        port,
    );

    let mut attributes = HashMap::new();
    attributes.insert("txtver", "1");
    match endpoint.deployment() {
        Deployment::Wan => attributes.insert("deployment", "WAN"),
        Deployment::Lan => attributes.insert("deployment", "LAN"),
    };
    if let Some(pairing_url) = endpoint.pairing_url() {
        attributes.insert("pairingUrl", pairing_url);
    }
    if let Some(longpolling_url) = endpoint.longpolling_url() {
        attributes.insert("longpollingUrl", longpolling_url);
    }
    if let Some(endpoint_name) = endpoint.endpoint_name() {
        attributes.insert("e_name", endpoint_name);
    }
    if let Some(endpoint_logo_url) = endpoint.endpoint_logo_url() {
        attributes.insert("e_logoUrl", endpoint_logo_url);
    }

    service.set_txt_record(TxtRecord::from(attributes));

    let mut advertised_service = MdnsServiceAsync::new(service).map_err(|_| Error::MdnsError)?;

    advertised_service.start().await.map_err(|_| Error::MdnsError)?;

    Ok(S2Advertisement {
        advertisement: advertised_service,
    })
}

pub struct S2Discoverer {
    browser: MdnsBrowserAsync,
}

pub enum DiscoveryEvent {
    NewEndpoint {
        hostname: String,
        endpoint: DiscoverableS2Endpoint,
    },
    RemovedEndpoint {
        hostname: String,
    },
}

impl S2Discoverer {
    pub async fn new(role: S2Role) -> Result<Self, Error> {
        // The unwrap on service type is fine as its arguments are always valid.
        let mut browser = MdnsBrowserAsync::new(MdnsBrowser::new(
            ServiceType::with_sub_types("s2emp", "tcp", vec![role.service_subtype()]).unwrap(),
        ))
        .map_err(|_| Error::MdnsError)?;

        browser.start().await.map_err(|_| Error::MdnsError)?;

        Ok(Self { browser })
    }

    pub async fn next_event(&mut self) -> Result<DiscoveryEvent, Error> {
        loop {
            let event = self
                .browser
                .next()
                .await
                .transpose()
                .map_err(|_| Error::MdnsError)
                .transpose()
                .unwrap_or(Err(Error::MdnsError))?;

            match event {
                zeroconf_tokio::BrowserEvent::Add(service_discovery) => {
                    let Some(endpoint) = DiscoverableS2Endpoint::from_discovery(&service_discovery) else {
                        continue;
                    };

                    return Ok(DiscoveryEvent::NewEndpoint {
                        hostname: service_discovery.name().clone(),
                        endpoint,
                    });
                }
                zeroconf_tokio::BrowserEvent::Remove(service_removal) => {
                    return Ok(DiscoveryEvent::RemovedEndpoint {
                        hostname: service_removal.name().clone(),
                    });
                }
            }
        }
    }
}
